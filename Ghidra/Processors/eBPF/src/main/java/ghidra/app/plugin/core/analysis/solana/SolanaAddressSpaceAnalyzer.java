/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.analysis.solana;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Solana address space analyzer.
 * 
 * Labels the standard Solana VM memory regions to improve decompilation clarity.
 * Regions defined by agave/solana-sbpf:
 *   PROGRAM: 0x100000000 (standard entry)
 *   STACK:   0x200000000
 *   HEAP:    0x300000000
 *   INPUT:   0x400000000
 */
public class SolanaAddressSpaceAnalyzer extends AbstractAnalyzer {

    private final static String PROCESSOR_NAME = "eBPF";

    private final static String NAME = "Solana Memory Map";
    private final static String DESCRIPTION = "Label authoritative Solana VM memory regions (Stack, Heap, Input)";

    public SolanaAddressSpaceAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.BLOCK_ANALYSIS.after());
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return PROCESSOR_NAME.equals(program.getLanguage().getProcessor().toString());
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        createMemoryBlock(program, "VM_STACK", 0x200000000L, 0x100000L, log); // 1MB Stack
        createMemoryBlock(program, "VM_HEAP",  0x300000000L, 0x8000L,   log); // 32KB Heap (standard)
        createMemoryBlock(program, "VM_INPUT", 0x400000000L, 0x100000L, log); // 1MB Input (variable)

        return true;
    }

    private void createMemoryBlock(Program program, String name, long start, long length, MessageLog log) {
        Memory memory = program.getMemory();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Address startAddr = space.getAddress(start);

        try {
            if (memory.getBlock(startAddr) == null) {
                MemoryBlock block = memory.createUninitializedBlock(name, startAddr, length, false);
                block.setRead(true);
                block.setWrite(true);
                block.setSourceName("Solana VM Map");
                
                if (log != null) {
                    log.appendMsg("Created Solana VM region: " + name + " at " + startAddr);
                }
            }
        } catch (Exception e) {
            // Ignore if already exists or overlap
        }
    }
}
