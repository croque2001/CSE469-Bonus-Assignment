Name: Cristian Roque
ID: 1223531036

Description: This program is analyzing the Master Boot Record (MBR) and the GUID Partition Table (GPT) of forensic disk images. Before doing so, this program calculates the hash values of each image: MD5, SHA256, SHA512. This program checks the type byte first before deciding whether to analyze the MBR or GPT. The type byte must be EE for GPT, otherwise it is MBR. For the MBR record, the partition type, name, starting sector, and partition size are displayed for each partition. Then it displays the 16 bytes starting at the offset from the current partition for those partitions. In the GPT record, for every partition, it displays the partition type GUID, starting and ending LBA's, and the partition name given the remaining bytes in each partition. This program is now able to support more than 1 file, can filter specific partition types for MBR, and support verbose mode for debugging purposes.

Portions of the code in this project were generated with the assistance from ChatGPT, an AI tool developed by OpenAI. Reference: OpenAI. (2024). ChatGPT [Large language model]. openai.com/chatgpt
