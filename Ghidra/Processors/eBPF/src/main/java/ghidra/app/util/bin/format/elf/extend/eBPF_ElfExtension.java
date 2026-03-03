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
package ghidra.app.util.bin.format.elf.extend;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.lang.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * eBPF ELF extension with Solana SBF support.
 *
 * Handles both standard eBPF (EM_BPF = 0xF7 = 247) and
 * Solana SBF (EM_SBF = 0x107 = 263) machine types.
 * Solana's LLVM backend emits EM_SBF for SBF v2 binaries.
 */
public class eBPF_ElfExtension extends ElfExtension {

    /** Solana SBF machine type (not yet in ElfConstants) */
    private static final short EM_SBF = 263;

    /**
     * Check if this is an eBPF or Solana SBF ELF.
     */
    private static boolean isBpfMachine(ElfHeader elf) {
        short machine = elf.e_machine();
        return (machine == ElfConstants.EM_BPF || machine == EM_SBF) && elf.is64Bit();
    }

    @Override
    public boolean canHandle(ElfHeader elf) {
        return isBpfMachine(elf);
    }

    @Override
    public boolean canHandle(ElfLoadHelper elfLoadHelper) {
        Language language = elfLoadHelper.getProgram().getLanguage();
        return canHandle(elfLoadHelper.getElfHeader()) &&
            "eBPF".equals(language.getProcessor().toString()) &&
            language.getLanguageDescription().getSize() == 64;
    }

    @Override
    public String getDataTypeSuffix() {
        return "eBPF";
    }

    @Override
    public void processGotPlt(ElfLoadHelper elfLoadHelper, TaskMonitor monitor) throws CancelledException {
        if (!canHandle(elfLoadHelper)) {
            return;
        }
        super.processGotPlt(elfLoadHelper, monitor);
    }
}

