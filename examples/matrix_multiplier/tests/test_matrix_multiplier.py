# TODO LICENSE

import math
import os
import sys
from pathlib import Path
from random import getrandbits
from typing import Any, Dict, List

import cocotb
from cocotb.binary import BinaryValue
from cocotb.clock import Clock
from cocotb.handle import SimHandleBase
from cocotb.queue import Queue
from cocotb.runner import get_runner
from cocotb.triggers import RisingEdge
from cocotbext.fcov import (
    CoverageModel,
    CoverageCollector,
    CoverGroup,
    CoverPoint,
    Cross,
    BinRange,
    BinExp,
    BinMinMax,
)


def log2Ceil(num):
    return int(math.ceil(math.log2(num)))


NUM_SAMPLES = int(os.environ.get("NUM_SAMPLES", 3000))
if cocotb.simulator.is_running():
    DATA_WIDTH = int(cocotb.top.DATA_WIDTH)
    A_ROWS = int(cocotb.top.A_ROWS)
    B_COLUMNS = int(cocotb.top.B_COLUMNS)
    A_COLUMNS_B_ROWS = int(cocotb.top.A_COLUMNS_B_ROWS)
    C_DATA_WIDTH = (2 * DATA_WIDTH) + log2Ceil(A_COLUMNS_B_ROWS)
else:
    DATA_WIDTH = int(os.getenv("DATA_WIDTH"))
    A_ROWS = int(os.getenv("A_ROWS"))
    B_COLUMNS = int(os.getenv("B_COLUMNS"))
    A_COLUMNS_B_ROWS = int(os.getenv("A_COLUMNS_B_ROWS"))
    C_DATA_WIDTH = (2 * DATA_WIDTH) + log2Ceil(A_COLUMNS_B_ROWS)


###########################
# Functional Coverage Model
###########################


class TransactionCoverGroup(CoverGroup):
    """number of consecutive transactions without latency"""
    def __init__(self, max=100, name=None):
        CoverGroup.__init__(self, name)
        self.cp = CoverPoint(range(1, max + 1))


class LatencyCoverGroup(CoverGroup):
    """
    number of cycles between transactions
    range bins + exp bins
    """
    def __init__(self, max=8191, exp_start=5, name=None):
        CoverGroup.__init__(self, name)
        stop_range = min(1 << (exp_start - 1), max + 1)
        bins = BinRange(stop_range) + BinExp(stop_range, max)
        self.cp = CoverPoint(bins)


class BusCoverage(CoverageModel):
    cg_trans = TransactionCoverGroup()
    cg_latency = LatencyCoverGroup()


bus_cov_in = BusCoverage("bus_cov_in_inst")
bus_cov_out = BusCoverage("bus_cov_out_inst")


class DataInCoverGroup(CoverGroup):
    a = [CoverPoint(BinMinMax(0, (1<<DATA_WIDTH) - 1, num=DATA_WIDTH//2)) for _ in range(A_ROWS * A_COLUMNS_B_ROWS * B_COLUMNS)]
    b = [CoverPoint(BinMinMax(0, (1<<DATA_WIDTH) - 1, num=DATA_WIDTH//2)) for _ in range(A_ROWS * A_COLUMNS_B_ROWS * B_COLUMNS)]
    cross_a_b = [Cross([a_i, b_i]) for a_i, b_i in zip(a, b)]


class DataOutCoverGroup(CoverGroup):
    c = [CoverPoint(BinMinMax(0, (((1<<DATA_WIDTH) - 1) ** 2) * A_COLUMNS_B_ROWS, num=C_DATA_WIDTH//2)) for _ in range(A_ROWS * B_COLUMNS)]


class MatrixMultiplicationCoverage(CoverageModel):
    cg_data_in = DataInCoverGroup()
    cg_data_out = DataOutCoverGroup()


matmul_cov = MatrixMultiplicationCoverage("matmul_cov_inst")


######################
# Testbench
######################


class DataValidMonitor:
    """
    Reusable Monitor of one-way control flow (data/valid) streaming data interface

    Args
        clk: clock signal
        valid: control signal noting a transaction occured
        datas: named handles to be sampled when transaction occurs
    """

    def __init__(
        self, clk: SimHandleBase, datas: Dict[str, SimHandleBase], valid: SimHandleBase
    ):
        self.values = Queue[Dict[str, int]]()
        self._clk = clk
        self._datas = datas
        self._valid = valid
        self._coro = None

    def start(self) -> None:
        """Start monitor"""
        if self._coro is not None:
            raise RuntimeError("Monitor already started")
        self._coro = cocotb.start_soon(self._run())

    def stop(self) -> None:
        """Stop monitor"""
        if self._coro is None:
            raise RuntimeError("Monitor never started")
        self._coro.kill()
        self._coro = None

    async def _run(self) -> None:
        while True:
            await RisingEdge(self._clk)
            if self._valid.value.binstr != "1":
                await RisingEdge(self._valid)
                continue
            self.values.put_nowait(self._sample())

    def _sample(self) -> Dict[str, Any]:
        """
        Samples the data signals and builds a transaction object

        Return value is what is stored in queue. Meant to be overriden by the user.
        """
        return {name: handle.value for name, handle in self._datas.items()}


class DataValidMonitorWithCoverage(DataValidMonitor):
    """
    DataValidMonitor With Coverage
    """

    def __init__(
        self,
        clk: SimHandleBase,
        datas: Dict[str, SimHandleBase],
        valid: SimHandleBase,
        dut: SimHandleBase,
        coverage: BusCoverage,
    ):
        DataValidMonitor.__init__(self, clk, datas, valid)
        self.dut = dut
        self._coverage = coverage
        self._coverage.connect(dut)
        cocotb.start_soon(self._collect_coverage())

    async def _collect_coverage(self) -> None:
        before_trans_latency = 0
        consecutive_trans = 0
        while True:
            await RisingEdge(self._clk)
            if self._valid.value.binstr != "1":
                before_trans_latency += 1
                continue
            if before_trans_latency == 0:
                consecutive_trans += 1
            else:
                if consecutive_trans != 0:
                    self._coverage.cg_trans.cp <= consecutive_trans
                    self._coverage.cg_trans.sample()
                self._coverage.cg_latency.cp <= before_trans_latency
                self._coverage.cg_latency.sample()
                consecutive_trans = 0
                before_trans_latency = 0


class MatrixMultiplierTester(CoverageCollector):
    """
    Reusable checker of a matrix_multiplier instance

    Args
        matrix_multiplier_entity: handle to an instance of matrix_multiplier
    """

    def __init__(
        self,
        matrix_multiplier_entity: SimHandleBase,
        input_cov_model: BusCoverage,
        output_cov_model: BusCoverage,
        block_cov_model: MatrixMultiplicationCoverage,
    ):
        self.dut = matrix_multiplier_entity

        self.input_mon = DataValidMonitorWithCoverage(
            clk=self.dut.clk_i,
            datas=dict(A=self.dut.a_i, B=self.dut.b_i),
            valid=self.dut.valid_i,
            dut=self.dut,
            coverage=input_cov_model,
        )

        self.output_mon = DataValidMonitorWithCoverage(
            clk=self.dut.clk_i,
            datas=dict(C=self.dut.c_o),
            valid=self.dut.valid_o,
            dut=self.dut,
            coverage=output_cov_model,
        )

        self._checker = None
        CoverageCollector.__init__(self, self.dut, block_cov_model)

    def start(self) -> None:
        """Starts monitors, model, and checker coroutine"""
        if self._checker is not None:
            raise RuntimeError("Monitor already started")
        self.input_mon.start()
        self.output_mon.start()
        self._checker = cocotb.start_soon(self._check())

    def stop(self) -> None:
        """Stops everything"""
        if self._checker is None:
            raise RuntimeError("Monitor never started")
        self.input_mon.stop()
        self.output_mon.stop()
        self._checker.kill()
        self._checker = None

    def model(self, a_matrix: List[int], b_matrix: List[int]) -> List[int]:
        """Transaction-level model of the matrix multipler as instantiated"""
        A_ROWS = self.dut.A_ROWS.value
        A_COLUMNS_B_ROWS = self.dut.A_COLUMNS_B_ROWS.value
        B_COLUMNS = self.dut.B_COLUMNS.value
        DATA_WIDTH = self.dut.DATA_WIDTH.value
        return [
            BinaryValue(
                sum(
                    [
                        a_matrix[(i * A_COLUMNS_B_ROWS) + n]
                        * b_matrix[(n * B_COLUMNS) + j]
                        for n in range(A_COLUMNS_B_ROWS)
                    ]
                ),
                n_bits=(DATA_WIDTH * 2) + math.ceil(math.log2(A_COLUMNS_B_ROWS)),
                bigEndian=False,
            )
            for i in range(A_ROWS)
            for j in range(B_COLUMNS)
        ]

    async def _check(self) -> None:
        while True:
            actual = await self.output_mon.values.get()
            expected_inputs = await self.input_mon.values.get()
            expected = self.model(
                a_matrix=expected_inputs["A"], b_matrix=expected_inputs["B"]
            )
            assert actual["C"] == expected

            """ Coverage Collect """
            self.input_collect(expected_inputs)
            self.output_collect(expected)

    def input_collect(self, input):
        A_ROWS = self.dut.A_ROWS.value
        A_COLUMNS_B_ROWS = self.dut.A_COLUMNS_B_ROWS.value
        B_COLUMNS = self.dut.B_COLUMNS.value

        a_matrix = input["A"]
        b_matrix = input["B"]

        for i in range(A_ROWS):
            for j in range(B_COLUMNS):
                for k in range(A_COLUMNS_B_ROWS):
                    mac_index = A_COLUMNS_B_ROWS * B_COLUMNS * i + A_COLUMNS_B_ROWS * j + k
                    self.cov.cg_data_in.a[mac_index].value = a_matrix[i * A_COLUMNS_B_ROWS + k].value
                    self.cov.cg_data_in.b[mac_index].value = b_matrix[k * B_COLUMNS + j].value
        self.cov.cg_data_in.sample()

    def output_collect(self, output):
        for i in range(A_ROWS):
            for j in range(B_COLUMNS):
                self.cov.cg_data_out.c[i * B_COLUMNS + j].value = output[i * B_COLUMNS + j].value
        self.cov.cg_data_out.sample()


@cocotb.test(
    expect_error=IndexError
    if cocotb.simulator.is_running() and cocotb.SIM_NAME.lower().startswith("ghdl")
    else ()
)
async def multiply_test(dut):
    """Test multiplication of many matrices."""

    cocotb.start_soon(Clock(dut.clk_i, 10, units="ns").start())
    tester = MatrixMultiplierTester(dut, bus_cov_in, bus_cov_out, matmul_cov)

    dut._log.info("Initialize and reset model")

    # Initial values
    dut.valid_i.value = 0
    dut.a_i.value = create_a(lambda x: 0)
    dut.b_i.value = create_b(lambda x: 0)

    # Reset DUT
    dut.reset_i.value = 1
    for _ in range(3):
        await RisingEdge(dut.clk_i)
    dut.reset_i.value = 0

    # start tester after reset so we know it's in a good state
    tester.start()

    dut._log.info("Test multiplication operations")

    # Do multiplication operations
    for i, (A, B) in enumerate(zip(gen_a(), gen_b())):
        await RisingEdge(dut.clk_i)
        dut.a_i.value = A
        dut.b_i.value = B
        dut.valid_i.value = 1

        await RisingEdge(dut.clk_i)
        dut.valid_i.value = 0

        if i % 100 == 0:
            dut._log.info(f"{i} / {NUM_SAMPLES}")

    await RisingEdge(dut.clk_i)


def create_matrix(func, rows, cols):
    return [func(DATA_WIDTH) for row in range(rows) for col in range(cols)]


def create_a(func):
    return create_matrix(func, A_ROWS, A_COLUMNS_B_ROWS)


def create_b(func):
    return create_matrix(func, A_COLUMNS_B_ROWS, B_COLUMNS)


def gen_a(num_samples=NUM_SAMPLES, func=getrandbits):
    """Generate random matrix data for A"""
    for _ in range(num_samples):
        yield create_a(func)


def gen_b(num_samples=NUM_SAMPLES, func=getrandbits):
    """Generate random matrix data for B"""
    for _ in range(num_samples):
        yield create_b(func)


def test_matrix_multiplier_runner():
    """Simulate the matrix_multiplier example using the Python runner.

    This file can be run directly or via pytest discovery.
    """
    hdl_toplevel_lang = os.getenv("HDL_TOPLEVEL_LANG", "verilog")
    sim = os.getenv("SIM", "icarus")

    proj_path = Path(__file__).resolve().parent.parent

    verilog_sources = []
    vhdl_sources = []
    build_args = []

    if hdl_toplevel_lang == "verilog":
        verilog_sources = [proj_path / "hdl" / "matrix_multiplier.sv"]

        if sim in ["riviera", "activehdl"]:
            build_args = ["-sv2k12"]

    elif hdl_toplevel_lang == "vhdl":
        vhdl_sources = [
            proj_path / "hdl" / "matrix_multiplier_pkg.vhd",
            proj_path / "hdl" / "matrix_multiplier.vhd",
        ]

        if sim in ["questa", "modelsim", "riviera", "activehdl"]:
            build_args = ["-2008"]
    else:
        raise ValueError(
            f"A valid value (verilog or vhdl) was not provided for TOPLEVEL_LANG={hdl_toplevel_lang}"
        )

    extra_args = []
    if sim == "ghdl":
        extra_args = ["--std=08"]

    parameters = {
        "DATA_WIDTH": "32",
        "A_ROWS": 10,
        "B_COLUMNS": 4,
        "A_COLUMNS_B_ROWS": 6,
    }

    # equivalent to setting the PYTHONPATH environment variable
    sys.path.append(str(proj_path / "tests"))

    runner = get_runner(sim)

    runner.build(
        hdl_toplevel="matrix_multiplier",
        verilog_sources=verilog_sources,
        vhdl_sources=vhdl_sources,
        build_args=build_args + extra_args,
        parameters=parameters,
        always=True,
    )

    runner.test(
        hdl_toplevel="matrix_multiplier",
        hdl_toplevel_lang=hdl_toplevel_lang,
        test_module="test_matrix_multiplier",
        test_args=extra_args,
    )


if __name__ == "__main__":
    test_matrix_multiplier_runner()
