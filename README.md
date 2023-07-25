
  # BM64 Analyzer
  This module requires an Async Serial Analyzers output, to decode and show the different commands/events sent over UART to the BM64.

  This module should recognize these 3 packet types:
  * *BM64 Proprietary control interface*
  * *HCI* - used for control
  * *HCI ISDAP* - used for file transfer

  This module for now just shows the commands etc, but not the actual parameters or data of the commands. This is viewable in the raw data, but the module could be expanded to decode this.

## Guide

1. Load the extension through Logic "Extentions" -> "Load Existing Extension..."
2. In the analyzers tab, you need to setup an "Async Serial" Analyzer to make the UART data available to this analyzer
3. Then you add the BM64 Analyzer and through the configuration select the corresponding Async Serial analyzer link.
4. You also need to select the direction "MCU -> BM64" or "BM64 -> MCU" as for some packets, commands and events are not distinguishable.
5. Now you should see a channel in the view showing the commands and events recognized.
