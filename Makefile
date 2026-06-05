NASM        := nasm
QEMU        := qemu-system-i386
DD          := dd

DISK_IMAGE  := sx-sandbox.img
DISK_SIZE   := 1474560

LOADER_BIN  := loader.bin
STAGE2_BIN  := stage2.bin
SANDBOX_BIN := sandbox.bin

LOADER_OFFSET  := 0
STAGE2_OFFSET  := 512
SANDBOX_OFFSET := 6656

LOADER_SECTORS  := 1
STAGE2_SECTORS  := 12
SANDBOX_SECTORS := 8

QEMU_FLAGS  := -drive format=raw,file=$(DISK_IMAGE) \
               -m 4M \
               -cpu 486 \
               -display curses \
               -no-reboot \
               -no-shutdown

QEMU_DEBUG_FLAGS := -drive format=raw,file=$(DISK_IMAGE) \
                    -m 4M \
                    -cpu 486 \
                    -display curses \
                    -no-reboot \
                    -no-shutdown \
                    -s -S

QEMU_SDL_FLAGS := -drive format=raw,file=$(DISK_IMAGE) \
                  -m 4M \
                  -cpu 486 \
                  -display sdl \
                  -no-reboot \
                  -no-shutdown

.PHONY: all clean run run-sdl debug disasm check-tools help

all: check-tools $(DISK_IMAGE)
	@echo ""
	@echo "  Build complete: $(DISK_IMAGE)"
	@echo "  Run with:  make run"
	@echo ""

$(DISK_IMAGE): $(LOADER_BIN) $(STAGE2_BIN) $(SANDBOX_BIN)
	@echo "  [IMG]  Creating blank disk image ($(DISK_SIZE) bytes)..."
	$(DD) if=/dev/zero of=$(DISK_IMAGE) bs=512 count=2880 status=none

	@echo "  [IMG]  Writing loader  -> sector 0"
	$(DD) if=$(LOADER_BIN)  of=$(DISK_IMAGE) bs=512 seek=0  conv=notrunc status=none

	@echo "  [IMG]  Writing stage2  -> sector 2 (offset $(STAGE2_OFFSET))"
	$(DD) if=$(STAGE2_BIN)  of=$(DISK_IMAGE) bs=512 seek=2  conv=notrunc status=none

	@echo "  [IMG]  Writing sandbox -> sector 14 (offset $(SANDBOX_OFFSET))"
	$(DD) if=$(SANDBOX_BIN) of=$(DISK_IMAGE) bs=512 seek=14 conv=notrunc status=none

	@echo "  [OK]   Disk image assembled successfully."

$(LOADER_BIN): loader.asm
	@echo "  [ASM]  Assembling loader.asm..."
	$(NASM) -f bin -o $@ $<
	@SIZE=$$(wc -c < $@); \
	if [ $$SIZE -ne 512 ]; then \
		echo "  [ERR]  loader.bin must be exactly 512 bytes (got $$SIZE)"; \
		exit 1; \
	fi
	@echo "  [OK]   loader.bin = 512 bytes (MBR)"

$(STAGE2_BIN): stage2.asm
	@echo "  [ASM]  Assembling stage2.asm..."
	$(NASM) -f bin -o $@ $<
	@SIZE=$$(wc -c < $@); \
	echo "  [OK]   stage2.bin = $$SIZE bytes ($$(( $$SIZE / 512 )) sectors)"
	@SIZE=$$(wc -c < $@); \
	if [ $$SIZE -gt 6144 ]; then \
		echo "  [WARN] stage2.bin exceeds 12 sector reservation ($$SIZE bytes)"; \
	fi

$(SANDBOX_BIN): sandbox.asm
	@echo "  [ASM]  Assembling sandbox.asm..."
	$(NASM) -f bin -o $@ $<
	@SIZE=$$(wc -c < $@); \
	echo "  [OK]   sandbox.bin = $$SIZE bytes ($$(( $$SIZE / 512 )) sectors)"
	@SIZE=$$(wc -c < $@); \
	if [ $$SIZE -gt 4096 ]; then \
		echo "  [WARN] sandbox.bin exceeds 8 sector reservation ($$SIZE bytes)"; \
	fi

run: $(DISK_IMAGE)
	@echo "  [RUN]  Launching in QEMU (curses terminal mode)..."
	$(QEMU) $(QEMU_FLAGS)

run-sdl: $(DISK_IMAGE)
	@echo "  [RUN]  Launching in QEMU (SDL window mode)..."
	$(QEMU) $(QEMU_SDL_FLAGS)

debug: $(DISK_IMAGE)
	@echo "  [DBG]  QEMU paused. Connect GDB with:"
	@echo "         gdb -ex 'target remote :1234' -ex 'set architecture i8086'"
	@echo "         Then: break *0x7c00   continue"
	$(QEMU) $(QEMU_DEBUG_FLAGS)

disasm: $(LOADER_BIN) $(STAGE2_BIN) $(SANDBOX_BIN)
	@echo ""
	@echo "=== LOADER DISASSEMBLY (loader.bin) ==="
	ndisasm -b 16 -o 0x7C00 $(LOADER_BIN)
	@echo ""
	@echo "=== STAGE2 DISASSEMBLY (stage2.bin) ==="
	ndisasm -b 16 -o 0x7E00 $(STAGE2_BIN)
	@echo ""
	@echo "=== SANDBOX DISASSEMBLY (sandbox.bin) ==="
	ndisasm -b 16 -o 0x9000 $(SANDBOX_BIN)

check-tools:
	@command -v $(NASM) >/dev/null 2>&1 || \
		{ echo "  [ERR]  nasm not found. Install: sudo apt install nasm"; exit 1; }
	@command -v $(QEMU) >/dev/null 2>&1 || \
		{ echo "  [ERR]  qemu-system-i386 not found. Install: sudo apt install qemu-system-x86"; exit 1; }
	@command -v $(DD) >/dev/null 2>&1 || \
		{ echo "  [ERR]  dd not found (should be part of coreutils)"; exit 1; }
	@echo "  [OK]   All required tools found."

clean:
	@echo "  [CLN]  Removing build artifacts..."
	rm -f $(LOADER_BIN) $(STAGE2_BIN) $(SANDBOX_BIN) $(DISK_IMAGE)
	@echo "  [OK]   Clean complete."

help:
	@echo ""
	@echo "  SX-SANDBOX Build System"
	@echo "  ─────────────────────────────────────────"
	@echo "  make            Build all binaries and disk image"
	@echo "  make run        Run in QEMU (curses/terminal mode)"
	@echo "  make run-sdl    Run in QEMU (SDL window)"
	@echo "  make debug      Run QEMU with GDB stub on :1234"
	@echo "  make disasm     Disassemble all binaries with ndisasm"
	@echo "  make clean      Remove all build artifacts"
	@echo "  make help       Show this message"
	@echo ""
	@echo "  Memory Layout:"
	@echo "  0x7C00  loader.asm   Stage 1 MBR (512 bytes)"
	@echo "  0x7E00  stage2.asm   Execution engine + shell (12 sectors)"
	@echo "  0x9000  sandbox.asm  Protection & analysis layer (8 sectors)"
	@echo "  0xA000  shellcode    Runtime payload injection target"
	@echo ""
	@echo "  Shell Commands (inside QEMU):"
	@echo "  help             Show command reference"
	@echo "  list             List available payloads"
	@echo "  sel <n>          Select payload by index"
	@echo "  run              Execute selected payload"
	@echo "  sandbox          Re-run sandbox environment checks"
	@echo "  dump <hex>       Hexdump 32 bytes at address"
	@echo "  info             Show system memory map"
	@echo "  clear            Clear execution log"
	@echo ""
