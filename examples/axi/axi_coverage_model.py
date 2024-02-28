###############################################################################
# Copyright (c) 2024 FuriosaAI, Inc
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.

# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL POTENTIAL VENTURES LTD BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
###############################################################################

import math
from typing import Optional
from enum import Enum, IntEnum
from dataclasses import dataclass
from cocotbext.fcov import (
    CoverageModel,
    CoverGroup,
    CoverPoint,
    Cross,
    BinRange,
    BinExp,
    BinOneHot,
    BinMinMax,
    BinBitwise,
    BinOutOfSpec,
    BinEnum,
)


def log2Ceil(num):
    return int(math.ceil(math.log2(num)))


class AxiBurstType(IntEnum):
    FIXED = 0b00
    INCR = 0b01
    WRAP = 0b10


class AxiResponse(IntEnum):
    OKAY = 0b00
    EXOKAY = 0b01
    SLVERR = 0b10
    DECERR = 0b11


class HandShakeState(IntEnum):
    IDLE = 0
    WAIT_FOR_VALID = 1
    WAIT_FOR_READY = 2
    HANDSHAKE = 3


class AxiSize(IntEnum):
    byte_1 = 1
    byte_2 = 2
    byte_4 = 4
    byte_8 = 8
    byte_16 = 16
    byte_32 = 32
    byte_64 = 64
    byte_128 = 128


class AxiLock(IntEnum):
    NORMAL_ACCESS = 0
    EXCLUSIVE_ACCESS = 1
    LOCKED_ACCESS = 2


class AxiProtectionPrivleged(IntEnum):
    UNPRIVILEGED = 0
    PRIVILEGED = 1


class AxiProtectionSecure(IntEnum):
    SECURE = 0
    NON_SECURE = 1


class AxiProtectionInstruction(IntEnum):
    INSTRUCTION = 0
    DATA = 1


class AxiWriteCache(Enum):
    DEVICE_NON_BUFFERABLE = 0
    DEVICE_BUFFERABLE = 1
    NORMAL_NON_CACHEABLE_NON_BUFFERABLE = 2
    NORMAL_NON_CACHEABLE_BUFFERABLE = 3
    WRITE_THROUGH_NO_ALLOCATE = 6
    WRITE_THROUGH_READ_ALLOCATE = 6
    WRITE_THROUGH_WRITE_ALLOCATE = (10, 14)
    WRITE_THROUGH_READ_AND_WRITE_ALLOCATE = 14
    WRITE_BACK_NO_ALLOCATE = 7
    WRITE_BACK_READ_ALLOCATE = 7
    WRITE_BACK_WRITE_ALLOCATE = (11, 15)
    WRITE_BACK_READ_AND_WRITE_ALLOCATE = 15


class AxiReadCache(Enum):
    DEVICE_NON_BUFFERABLE = 0
    DEVICE_BUFFERABLE = 1
    NORMAL_NON_CACHEABLE_NON_BUFFERABLE = 2
    NORMAL_NON_CACHEABLE_BUFFERABLE = 3
    WRITE_THROUGH_NO_ALLOCATE = 10
    WRITE_THROUGH_READ_ALLOCATE = (6, 14)
    WRITE_THROUGH_WRITE_ALLOCATE = 10
    WRITE_THROUGH_READ_AND_WRITE_ALLOCATE = 14
    WRITE_BACK_NO_ALLOCATE = 11
    WRITE_BACK_READ_ALLOCATE = (7, 15)
    WRITE_BACK_WRITE_ALLOCATE = 11
    WRITE_BACK_READ_AND_WRITE_ALLOCATE = 15


class AxiHandshake(CoverGroup):
    cp_aw = CoverPoint(BinEnum(HandShakeState))
    cp_w = CoverPoint(BinEnum(HandShakeState))
    cp_b = CoverPoint(BinEnum(HandShakeState))
    cp_ar = CoverPoint(BinEnum(HandShakeState))
    cp_r = CoverPoint(BinEnum(HandShakeState))
    cp_cross_aw_ar = Cross([cp_aw, cp_ar])
    cp_cross_aw_w = Cross([cp_aw, cp_w])
    cp_cross_aw_r = Cross([cp_aw, cp_r])
    cp_cross_aw_b = Cross([cp_aw, cp_b])
    cp_cross_ar_w = Cross([cp_ar, cp_w])
    cp_cross_ar_b = Cross([cp_ar, cp_b])
    cp_cross_ar_r = Cross([cp_ar, cp_r])
    cp_cross_w_r = Cross([cp_w, cp_r])
    cp_cross_w_b = Cross([cp_w, cp_b])
    cp_cross_r_b = Cross([cp_r, cp_b])


class AxiConsecutiveHandshake(CoverGroup):
    cp = CoverPoint(BinExp(128) + [range(128, 1 << 16)], width=32)


class AxiAddressChannel(CoverGroup):
    def __init__(self, config):
        CoverGroup.__init__(self)

        if config.has_toggle_coverage:
            self.cp_address = CoverPoint(BinBitwise(config.addr_width))
            self.cp_user = CoverPoint(
                BinBitwise(config.user_req_width) if config.user_req_width else BinOutOfSpec()
            )

        self.cp_burst_type = CoverPoint(BinEnum(AxiBurstType))
        self.cp_burst_size = CoverPoint(BinOneHot(int(math.log2(config.data_width >> 3)) + 1))
        self.cp_burst_len = CoverPoint(BinRange(1, 257))
        self.cp_cross_len_type = Cross([self.cp_burst_len, self.cp_burst_type])

        self.cp_protection = CoverPoint(BinBitwise(3) if config.has_prot else BinOutOfSpec())
        self.cp_lock = CoverPoint(BinEnum(AxiLock) if config.has_lock else BinOutOfSpec())
        self.cp_region = CoverPoint(BinRange(16) if config.has_region else BinOutOfSpec())
        self.cp_qos = CoverPoint(BinRange(16) if config.has_qos else BinOutOfSpec())


class AxiWriteAddressChannel(AxiAddressChannel):
    def __init__(self, config):
        AxiAddressChannel.__init__(self, config)

        self.cp_cache = CoverPoint(BinEnum(AxiWriteCache) if config.has_cache else BinOutOfSpec())
        self.cp_id = CoverPoint(BinRange(1 << config.id_w_width))


class AxiReadAddressChannel(AxiAddressChannel):
    def __init__(self, config):
        AxiAddressChannel.__init__(self, config)

        self.cp_cache = CoverPoint(BinEnum(AxiReadCache) if config.has_cache else BinOutOfSpec())
        self.cp_id = CoverPoint(BinRange(1 << config.id_r_width))


class AxiWriteDataChannel(CoverGroup):
    def __init__(self, config):
        CoverGroup.__init__(self)
        if config.has_toggle_coverage:
            self.cp_data = CoverPoint(BinBitwise(config.data_width))
            self.cp_user = CoverPoint(
                BinBitwise(config.user_data_width) if config.user_data_width else BinOutOfSpec()
            )


class AxiReadResponseChannel(CoverGroup):
    def __init__(self, config):
        CoverGroup.__init__(self)
        self.cp_resp = CoverPoint(BinEnum(AxiResponse))
        if config.has_toggle_coverage:
            self.cp_data = CoverPoint(BinBitwise(config.data_width))
            self.cp_user = CoverPoint(
                BinBitwise(config.user_data_width + config.user_resp_width)
                if config.user_data_width or config.user_resp_width
                else BinOutOfSpec()
            )


class AxiWriteResponseChannel(CoverGroup):
    def __init__(self, config):
        CoverGroup.__init__(self)
        self.cp_resp = CoverPoint(BinEnum(AxiResponse))
        if config.has_toggle_coverage:
            self.cp_user = CoverPoint(
                BinBitwise(config.user_resp_width) if config.user_resp_width else BinOutOfSpec()
            )


class AxiLatencyWriteAddress(CoverGroup):
    cp_aw_to_first_w = CoverPoint(BinRange(100, 1 << 15) + BinExp(100, base=10), width=32)


class AxiLatencyData(CoverGroup):
    cp_d_to_d = CoverPoint(
        [1, range(2, 5), range(5, 11), range(11, 101), range(101, 1 << 15)], width=32
    )


class AxiLatencyWriteResponse(CoverGroup):
    cp_last_w_to_b = CoverPoint(
        [
            1,
            range(2, 11),
            range(11, 101),
            range(101, 1001),
            range(1001, 4001),
            range(4001, 8001),
            range(8001, 1 << 15),
        ],
        width=32,
    )


class AxiLatencyReadAddress(CoverGroup):
    cp_ar_to_first_r = CoverPoint([1, range(2, 11), range(11, 101), range(101, 1 << 15)], width=32)


class AxiMor(CoverGroup):
    def __init__(self, config):
        CoverGroup.__init__(self)
        self.cp_mor = CoverPoint(
            BinRange(1, config.outstanding_write_requests + 1)
            if isinstance(config.outstanding_write_requests, int)
            else BinOutOfSpec()
        )


class AxiReorder(CoverGroup):
    def __init__(self, config):
        CoverGroup.__init__(self)
        max_reorder = config.reorder_depth
        if max_reorder == 0:
            self.cp_depth = CoverPoint(BinOutOfSpec())
        elif max_reorder <= 2:
            self.cp_depth = CoverPoint(BinRange(max_reorder))
        else:
            self.cp_depth = CoverPoint(BinMinMax(0, max_reorder, num=max(3, max_reorder // 4)))


class AxiReadInterleavingId(CoverGroup):
    def __init__(self, config):
        CoverGroup.__init__(self)
        if config.enable_response_interleaving:
            self.cp_id1 = CoverPoint(BinRange(1 << config.id_r_width))
            self.cp_id2 = CoverPoint(BinRange(1 << config.id_r_width))
            self.cp_corss_id1_id2 = Cross([self.cp_id1, self.cp_id2])
        else:
            self.cp_id1 = CoverPoint(BinOutOfSpec())
            self.cp_id2 = CoverPoint(BinOutOfSpec())


class AxiReadInterleavingData(CoverGroup):
    def __init__(self, config):
        CoverGroup.__init__(self)
        if config.enable_response_interleaving:
            self.cp_id = CoverPoint(BinRange(1 << config.id_r_width))
            self.cp_data_count = CoverPoint(BinRange(129) + [range(129, (1 << 15) - 1)])
            self.cross_id_data_count = Cross([self.cp_id, self.cp_data_cnt])
        else:
            self.cp_id = CoverPoint(BinOutOfSpec())
            self.cp_data_count = CoverPoint(BinOutOfSpec())


class AxiUnalignedStrobe(CoverGroup):
    def __init__(self, config):
        CoverGroup.__init__(self)
        self.cp_unaligned_strobe = (
            CoverPoint(self.unaligned_strobe(log2Ceil(config.data_width >> 3)), format="x")
            if not config.aligned_address
            else CoverPoint(BinOutOfSpec())
        )

    def unaligned_strobe(self, max_burst_size):
        for i in range(1 << max_burst_size):
            strobe = 0
            for j in range(1 << max_burst_size):
                if j >= i:
                    strobe += 1 << j
            yield strobe


class AxiNarrowTransfer(CoverGroup):
    def __init__(self, config):
        CoverGroup.__init__(self)
        self.cp_strobe = CoverPoint(self.narrow_strobe(config.data_width >> 3), format="x")
        self.cp_burst_type = CoverPoint(BinEnum(AxiBurstType))
        self.cp_burst_len = CoverPoint(BinRange(1, 257))
        self.cp_burst_size = CoverPoint(BinOneHot(int(math.log2(config.data_width >> 3)) + 1))
        self.cp_cross_narrow = Cross([self.cp_burst_type, self.cp_burst_len, self.cp_burst_size])

    def narrow_strobe(self, bus_byte_width):
        for i in range(log2Ceil(bus_byte_width)):
            size = 1 << i
            for j in range(bus_byte_width // size):
                strobe = ((1 << size) - 1) << (j * size)
                yield (f"en{size}byte_{hex(strobe)}", strobe)


class AxiProtocolCoverage(CoverageModel):
    def __init__(self, config):
        self.cg_axi_ch_aw = AxiWriteAddressChannel(config)
        self.cg_axi_ch_w = AxiWriteDataChannel(config)
        self.cg_axi_ch_ar = AxiAddressChannel(config)
        self.cg_axi_ch_b = AxiWriteResponseChannel(config)
        self.cg_axi_ch_r = AxiReadResponseChannel(config)
        self.cg_axi_mor_wlast = AxiMor(config)
        self.cg_axi_mor_bresp = AxiMor(config)
        self.cg_axi_mor_rlast = AxiMor(config)
        self.cg_axi_read_reorder = AxiReorder(config)
        self.cg_axi_read_interleaving_id = AxiReadInterleavingId(config)
        self.cg_axi_read_interleaving_data = AxiReadInterleavingData(config)
        self.cg_axi_narrow = AxiNarrowTransfer(config)
        self.cg_axi_unaligned_strobe = AxiUnalignedStrobe(config)
        self.cg_handshake = AxiHandshake()
        self.cg_axi_consec_aw = AxiConsecutiveHandshake()
        self.cg_axi_consec_ar = AxiConsecutiveHandshake()
        self.cg_axi_consec_w = AxiConsecutiveHandshake()
        self.cg_axi_consec_b = AxiConsecutiveHandshake()
        self.cg_axi_consec_r = AxiConsecutiveHandshake()
        self.cg_axi_latency_aw = AxiLatencyWriteAddress()
        self.cg_axi_latency_w = AxiLatencyData()
        self.cg_axi_latency_b = AxiLatencyWriteResponse()
        self.cg_axi_latency_ar = AxiLatencyReadAddress()
        self.cg_axi_latency_r = AxiLatencyData()
        CoverageModel.__init__(self, config.coverage_instance)


@dataclass
class AxiConfig:
    addr_width: int = 64
    data_width: int = 1024
    id_r_width: int = 32
    id_w_width: int = 32
    has_region: bool = False
    has_qos: bool = False
    has_lock: bool = False
    has_cache: bool = False
    has_prot: bool = False
    user_data_width: int = 0
    user_req_width: int = 0
    user_resp_width: int = 0
    aligned_address: bool = False
    reorder_depth: int = 0
    outstanding_write_requests: Optional[int] = None
    enable_response_interleaving: bool = False
    has_toggle_coverage: bool = True
    coverage_instance: Optional[str] = None


axi_config_example = AxiConfig()
axi_coverage_model = AxiProtocolCoverage(axi_config_example)
