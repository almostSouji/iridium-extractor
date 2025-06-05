#!/usr/bin/env python3

"""
Find points of interest in iridium recordings pre-processed by iridium-toolkit
https://github.com/muccc/iridium-toolkit

This may aid in guiding further manual exploration but should not be seen as fully automated extraction of interesting data

Extracted Data:
* Voice frames
* SBD data pages
* IIP data pages
* Frame type mix distribution
* Domain-likes (with registered TLDs)
* High priority TLDs
* IPv4-likes

IIP labels:
* #structured (byte entropy in range (3.5, 5.0) suggests english text or similarly structured data)
* #compressed (byte entropy in range 7.5+ suggests compressed or encrypted data)
* #maritime (Iridium Safetycast messages)

About the Approach:
Iridium traffic is split into communication channels.
Each channel consists of a time slot within a repeating 90ms timeframe (TDMA) and a carrier frequency access (FDMA).
Due to consequential overlaps in the time domain, this script only considers the frequency access and substitutes the time dimension with a frametype catgorisation and filtering.
This can cause false positives if there are frames from time-wise neighbouring communication channels within the same frequency allotment.

To determine so-called FDMA *runs* (sequences of frames in the same access range), a moving window categorization with a timeout is applied.
This is necessary because of a notable drift in carrier frequency, caused by Doppler Shift of the moving satellite vehicle and the stationary observer.
Using the frequency access as calculated runs into visually trivially connected FDMA runs being split as the access boundary is passed during drift.

Notes:
* All recordings used with this script have been recorded with a modified version of gr-iridium with changed timestamp logic
* TDMA (time domain) association may be feasible in accurate recordings with the original timestamp logic
* FDMA runs subsitute proper Doppler shift correction
* IPv4 detection is not particularly reliable due to the lax formatting requirements and accidental pattern matches
* Frequencies are derived from MANUAL FOR ICAO AERONAUTICAL MOBILE SATELLITE (ROUTE) SERVICE Part 2-IRIDIUM DRAFT v4.0 21 March 2007
* A lot of conversation happens in encrypted or compressed streams or proprietary protocols, deriving useful information from these is not attempted.
* Regarding further processing of voice frames, see https://github.com/muccc/iridium-toolkit

Resources:
* https://github.com/muccc/gr-iridium
* https://github.com/muccc/iridium-toolkit
* https://en.wikipedia.org/wiki/Doppler_effect
* https://en.wikipedia.org/wiki/Entropy_(information_theory)
* www.decodesystems.com/iridium.html
* Iridium SafetyCast: https://wwwcdn.imo.org/localresources/en/OurWork/Safety/Documents/Documents%20relevant%20to%20GMDSS/MSC.1-Circ.1613-Rev.2.pdf
"""

import argparse
import os
from pathlib import Path
from math import floor, log
from collections import Counter
from typing import NamedTuple
import re
from dataclasses import dataclass
import json
import tldextract
import sys


class FrameData(NamedTuple):
    raw: str
    frametype: str
    frequency: int
    timestamp: float
    sequence: int | None
    ascii_data: str | None
    data_bytes: str | None
    framesubtype: str | None


@dataclass
class FdmaRunData:
    frames: list[FrameData]
    center_frequency: int
    timestamp: float


class IIPPage(NamedTuple):
    ascii: str
    bytes: str


parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument(
    "-o",
    "--outdir",
    help="Directory to write output to",
    metavar="[outdir]",
    required=False,
    default="./_extracted",
)
parser.add_argument(
    "--force",
    help="Overwrite data in the out directory, if it already exists",
    default=False,
    action="store_true",
)
parser.add_argument(
    "-p",
    "--prefilter",
    help="Discard simplex and other spammy frames (may decrease accurracy, but speeds the processing up substantially)",
    action="store_true",
)
parser.add_argument("file", help="Input file")

args = parser.parse_args()
outdir = os.path.realpath(args.outdir)

Path(outdir).mkdir(parents=True, exist_ok=args.force)

IRIDIUM_BASE_FREQUENCY = 1_616_000_000
IRIDIUM_SUBBAND_WDTH = 1_000_000 / 3
IRIDIUM_CHANNEL_WIDTH = 1e7 / (30 * 8)  # 30 sub-bands with 8 frequency accesses each
IRIDIUM_SIMPLEX_BASE_FREQUENCY = IRIDIUM_BASE_FREQUENCY + (
    30 * 8 * IRIDIUM_CHANNEL_WIDTH
)
SIMPLEX_CHANNEL_PLACEHOLDER = -1
CENTER_FREQ_TOLERANCE = IRIDIUM_CHANNEL_WIDTH / 4
TIME_DELTA_TOLERANCE_MS = 60_000

SBD_FRAMETYPES = ["IDA", "I36"]
VOICE_FRAMETYPES = ["VOC"]
IIP_FRAMETYPES = ["IIP", "IIU"]
DEBUG_FRAMETYPES = ["ERR", "RAW", "IRI"]
DISCARD_FRAMETYPES = ["IRA", "IMS", "ITL", "INP", "IBC", "IAQ", "ISY"]

MISSING_TOKEN_PLACEHOLDER = "[missing]"
HIGH_PRIORITY_TLDS = ["mil", "gov", "airforce", "army", "navy"]


def freq_to_subchannel(freq: int) -> int:
    """
    Get the frequency channel from the provided carrier frequency
    """
    res = floor(((freq - IRIDIUM_BASE_FREQUENCY) // IRIDIUM_SUBBAND_WDTH) + 1)
    return res if res <= 30 else SIMPLEX_CHANNEL_PLACEHOLDER


def freq_to_access(freq: int) -> int:
    """
    Get the frequency access from the provided carrier frequency
    """
    if freq >= IRIDIUM_SIMPLEX_BASE_FREQUENCY:
        return (
            floor((freq - IRIDIUM_SIMPLEX_BASE_FREQUENCY) // IRIDIUM_SUBBAND_WDTH) + 1
        )
    return (
        floor(
            ((freq - IRIDIUM_BASE_FREQUENCY) % IRIDIUM_SUBBAND_WDTH)
            / IRIDIUM_CHANNEL_WIDTH
        )
        + 1
    )


def is_bytes(chunk: str) -> bool:
    """
    Check whether the provided chunk is delimited by brackets, indicating a byte array
    """
    return chunk.startswith("[") and chunk.endswith("]")


def prepare_bytes(chunk: str) -> str:
    """
    Prepare the provided byte array by removing delimiters and surrounding brackets
    """
    return chunk.removeprefix("[").removesuffix("]").replace(".", "").strip()


def entropy(text: str | bytes) -> float:
    """
    Shannon's Entropy
    https://en.wikipedia.org/wiki/Entropy_(information_theory)
    """
    charcounts = Counter(text)
    probabilities = [float(charcounts[c] / len(text)) for c in charcounts]
    return -sum([p * log(p) / log(2.0) for p in probabilities])


last_timestamp = 0
frametype_counter = Counter()
data: list[FrameData] = []
fdma_runs: list[FdmaRunData] = []

with open(args.file) as f:
    for line_num, line in enumerate(f):
        if line_num % 1_000 == 0:
            print(f"Processing line {line_num}")

        line_num += 1
        line = line.strip()

        #  partial header parsing
        frametype, begin_of_recording, time_ms, frequency, *rest = line.split()
        frametype = frametype.removesuffix(":")

        if frametype in DEBUG_FRAMETYPES:
            # ignore debug frame types
            continue

        frequency = int(frequency)

        ms, _, frac = time_ms.partition(".")
        frac += "0" * (6 - len(frac))
        time_ns = int(ms) * 1e6 * int(frac)
        time_ms = float(time_ms)

        begin_of_recording_timestamp_s = int(begin_of_recording.split("-")[1])
        timestamp = begin_of_recording_timestamp_s * 1e3 + time_ms

        assert (
            timestamp > last_timestamp
        ), "Timestamps should be monotonously increasing"

        frametype_counter.update({frametype: 1})

        subtype = seq = ascii_data = data_bytes = None

        if frametype in IIP_FRAMETYPES:
            seen_ip_prefix = False
            for chunk in rest:
                if "type:" in chunk:
                    subtype = chunk.removeprefix("type:")
                elif "seq=" in chunk:
                    seq = int(chunk.removeprefix("seq="))
                elif "IP:" in chunk:
                    seen_ip_prefix = True
                elif seen_ip_prefix:
                    if ascii_data is None:
                        ascii_data = ""
                    ascii_data += chunk + " "
                elif is_bytes(chunk):
                    data_bytes = prepare_bytes(chunk)

        if frametype in SBD_FRAMETYPES:
            seen_sbd_prefix = False
            for chunk in rest:
                if is_bytes(chunk):
                    data_bytes = prepare_bytes(chunk)
                elif chunk.startswith("SBD"):
                    seen_sbd_prefix = True
                elif seen_sbd_prefix:
                    if ascii_data == None:
                        ascii_data = ""
                    ascii_data += chunk + ""

        frame = FrameData(
            raw=line,
            frametype=frametype,
            frequency=frequency,
            timestamp=timestamp,
            sequence=seq,
            ascii_data=ascii_data.strip() if ascii_data else None,
            data_bytes=re.sub(r"[^a-fA-F0-9]", "", data_bytes) if data_bytes else None,
            framesubtype=subtype,
        )

        if args.prefilter:
            if frame.frametype in DISCARD_FRAMETYPES:
                continue

        for i in reversed(range(len(fdma_runs))):
            run = fdma_runs[i]

            lower_bound = run.center_frequency - CENTER_FREQ_TOLERANCE
            upper_bound = run.center_frequency + CENTER_FREQ_TOLERANCE
            time_delta = timestamp - run.timestamp

            if lower_bound <= frequency <= upper_bound:
                if time_delta > TIME_DELTA_TOLERANCE_MS:
                    continue

                run.frames.append(frame)
                run.center_frequency = frame.frequency
                run.timestamp = frame.timestamp
                break
        else:
            fdma_runs.append(
                FdmaRunData(
                    frames=[frame],
                    center_frequency=frame.frequency,
                    timestamp=frame.timestamp,
                )
            )
    f.close()

with open(f"{outdir}/frametypemix.json", "w+") as f:
    f.write(json.dumps(dict(frametype_counter.items()), indent=4))
    f.close()

registered_domain_counter = Counter()
priority_domain_counter = Counter()
ipv4_counter = Counter()

for run_id, run in enumerate(fdma_runs):
    if run_id % 1_000 == 0:
        print(f"Processing run {run_id}/{len(fdma_runs)}", file=sys.stderr)

    voice: list[FrameData] = []
    sbd: list[FrameData] = []
    iip: list[FrameData] = []

    for frame in run.frames:
        if frame.frametype in VOICE_FRAMETYPES:
            # voice frames are dumped as-is
            voice.append(frame)
        elif frame.frametype in SBD_FRAMETYPES and frame.ascii_data is not None:
            # sbd pages with text payload
            sbd.append(frame)
        elif (
            frame.frametype in IIP_FRAMETYPES
            and frame.ascii_data is not None
            and frame.framesubtype == "04"
        ):
            # iip frames with text payload and subtype 04
            # only subtype 04 has a text payload
            iip.append(frame)

    # process voice frames
    if len(voice) >= 1:
        voicerun_dir = f"{outdir}/voice"
        Path(voicerun_dir).mkdir(parents=True, exist_ok=True)

        with open(f"{voicerun_dir}/voice-{run_id}.parsed", "w+") as f:
            for frame in voice:
                f.write(f"{frame.raw}")
            f.close()

    # process sbd frames
    if len(sbd) >= 1:
        # frames with suitable byte entropy
        filtered = [
            frame
            for frame in sbd
            if frame.data_bytes is not None
            and 3.2 < entropy(bytes.fromhex(frame.data_bytes)) < 5.0
        ]

        if len(filtered) >= 1:
            page = "".join(
                [frame.ascii_data for frame in filtered if frame.ascii_data is not None]
            )
            page_entropy = entropy(page)

            # page with suitable page ascii entropy
            if 3.2 < page_entropy < 5.0:
                with open(f"{outdir}/sbd.txt", "a+") as f:
                    f.writelines([f"#{run_id} e:{page_entropy}", "\n", page, "\n\n"])
                    f.close()

    # process iip frames
    if len(iip) >= 1:
        pages: list[IIPPage] = []
        page = ""
        page_hex = ""
        previous_sequence = None

        for frame in iip:
            if previous_sequence is not None:
                sequence_delta = frame.sequence - previous_sequence
                if previous_sequence > frame.sequence or sequence_delta > 5:
                    # new page, flipped polarity or large gap
                    pages.append(IIPPage(ascii=page, bytes=page_hex))
                    page = ""
                    page_hex = ""
                else:
                    # acceptable gap, fill
                    fill_amount = sequence_delta - 1
                    page += MISSING_TOKEN_PLACEHOLDER * fill_amount
                    page_hex += "2E" * fill_amount
            # append frame to page

            assert (
                frame.data_bytes is not None
            ), "should not be None as per filter expression"
            assert (
                frame.ascii_data is not None
            ), "Should not be None as per filter expression"

            page += frame.ascii_data
            page_hex += frame.data_bytes
            previous_sequencey = frame.sequence
        if len(page):
            # flush remaining page
            pages.append(IIPPage(ascii=page, bytes=page_hex))

        # pages with suitable byte entropy or no gaps
        pages = [
            page
            for page in pages
            if 3.2 < entropy("".join(page.bytes)) < 5.0
            or MISSING_TOKEN_PLACEHOLDER not in page.ascii
        ]

        if len(pages):
            run_string = ""
            run_hex = ""

            for page in pages:
                if "MMSI" in page.ascii:
                    with open(f"{outdir}/mmsi.txt", "a+") as f:
                        f.write(f"{page.ascii}\n")
                        f.close()
                    with open(f"{outdir}/mmsi.bits", "ab+") as f:
                        f.write(bytes.fromhex(page.bytes))
                        f.close()
                run_string += page.ascii
                run_hex += page.bytes

            run_entropy = entropy(bytes.fromhex(run_hex))
            in_english_entropy_range = 3.5 < run_entropy < 5.0
            in_compressed_entropy_range = run_entropy > 7.5

            for match in re.finditer(
                r"(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]))\.[a-z]{2,}",
                run_string,
            ):
                key = tldextract.extract(match.group(0)).registered_domain
                for hp in HIGH_PRIORITY_TLDS:
                    if key.endswith(hp):
                        priority_domain_counter.update({key: 1})
                if len(key):
                    registered_domain_counter.update({key: 1})

            for match in re.finditer(
                r"((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}", run_string
            ):
                ipv4_counter.update({match.group(0): 1})

            headerparts = [f"#{run_id} e:{run_entropy}"]

            if in_english_entropy_range:
                headerparts.append("#structured")
            if in_compressed_entropy_range:
                headerparts.append("#compression")
            if "MMSI" in run_string:
                headerparts.append("#maritime")

            with open(f"{outdir}/iip-pages.txt", "a+") as f:
                f.writelines([" ".join(headerparts), "\n", run_string, "\n\n"])
                f.close()

# dump counters to file
for counter, filename in [
    (ipv4_counter, "ipv4"),
    (priority_domain_counter, "prioritydomains"),
    (registered_domain_counter, "registered-domains"),
]:
    if len(counter) < 1:
        continue

    with open(f"{outdir}/{filename}.csv", "w+") as f:
        f.writelines([f"{label},{count}\n" for label, count in counter.most_common()])
