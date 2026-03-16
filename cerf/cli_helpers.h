#pragma once

class ArmCpu;

void PrintUsage(const char* prog);
void DumpRegisters(ArmCpu& cpu);

/* Wait for child threads / message pump after main CPU halts */
void HandlePostHalt(ArmCpu& cpu);
