# Iridium Extractor

A small proof of concept python script to extract useful information from preparsed iridium signals.
The applied filtering and labels may aid in guiding further research and manual exploration, but should not be seen as a fully automated extraction service without false positives.

# Prerequisites

This script expects `.parsed` files obtained from parsing gr-iridium [^1] recordings with `python3 iridium-parser.py -p output.bits` as provided by the iridium-toolkit project [^2].
The only dependency this reworked version of the script requires is the `tldextract` library (if not desired, this part can be stripped fairly easily as it is not vital for frame processing)

[^1]: https://github.com/muccc/gr-iridium
[^2]: https://github.com/muccc/iridium-toolkit

# Extraction

Iridium-extractor currently finds and processes the following information, after re-assembling continuous frequency runs:

* Voice frames (saved as-is)
* Short Burst Data frames (filtered)
* IIP data pages (filtered)
* TLDs (separate high priority TLDs)
* IPv4-like phrases
* Frame mix distribution statistics
* Iridium SafetyCast messages

# Labels

IIP (Iridium IP) data pages are labeled with the run id (int) and the byte entropy [^3] of the page. For ease of use with text search tools, the following additional labels are applied:

* #structured - byte entropy in range (3.5, 5.0) suggesting english text or simiarly structured data [^4]
* #compressed - byte entropy in range (7.5, ...) suggesting compressed or encrypted data [^4]
* #maritime - Iridium SafetyCast [^5] messages

[^3]: https://en.wikipedia.org/wiki/Entropy_(information_theory)
[^4]: https://github.com/gchq/CyberChef/blob/c57556f49f723863b9be15668fd240672cd15b09/src/core/operations/Entropy.mjs#L354-L355
[^5]: https://wwwcdn.imo.org/localresources/en/OurWork/Safety/Documents/Documents%20relevant%20to%20GMDSS/MSC.1-Circ.1613-Rev.2.pdf

# Iridium SafetyCast

Data labeled with `#maritime` contain a key phrase of the Iridium SafetyCast [^5] protocol. It is used for maritime distress signaling.
The MMSI [^6] included in these pages can be resolved to ships using services like [vesselfinder](https://www.vesselfinder.com/).

Some SafetyCast data pages include a `START:...:COMPRESSION:1:<data>:STOP` segment. The `<data>` portion can be retrieved from the extracted `.bits` files with a hex editor (landmark being the `COMPRESSION:1` phrase up to `STOP`) and translated and decompressed with [cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')Zlib_Inflate(0,0,'Adaptive',false,false)) [^7] using the `From_Hex` > `Zlib_Inflate` operations.

[^6]: https://en.wikipedia.org/wiki/Maritime_Mobile_Service_Identity
[^7]: https://github.com/gchq/CyberChef

# About

Iridium extractor is a reworked part of the result of my bachelor's thesis.
I don't currently plan on improving or extending this project substantially, though that may change in the future, should time, curiosity and interest permit it.

Iridium communication channels use a combined TDMA/FDMA approach and each channel consists of a frequency access range and allocated timeslot in a repeating 90ms timeframe.
The data for my thesis was obtained using a version of gr-iridium [^1] with modified timestamp logic. In my research I have noticed substantial overlaps to the point where determining the TDMA slot of any given frame was not feasible.
As a result this script substitutes the TDMA split by processing sequential FDMA data based on frame type. This approach inevitably causes false positives for neighbouring time slots in the same frequency access range with the same frame types. Since most data frames have unknown contents or no text payload, the occurrence of these overlaps are not as substantial as initially thought.

# Outline of the Processing Pipeline

1. Input: output file of `iridium-parser.py` of the iridium-toolkit project [^2]
2. Partially parse the required fields based on frame type
3. Count occurrences of each frame type for statistics
4. Cluster frames to FDMA runs using a moving window with the tolerance of 1/4th frequency access width and a 60s timeout, preferring recent runs
5. For each FDMA run, determine the voice, short burst data, and iridium IP frames in the run
6. Write voice frames to file
7. Stitch short burst data pages that pass a byte and page entropy threshold
8. Stitch ip data pages based on sequence numbers, filling gaps with a placeholder and considering a page break if the gap becomes too large
9. Extract TLDs, IPs from reassembled IP pages
10. Label ip pages based on entropy thresholds and frame contents
11. Write findings into files
