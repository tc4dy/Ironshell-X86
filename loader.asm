BITS 16
ORG 0x7C00

LOADER_VERSION      equ 0x0102
STAGE2_LOAD_SEG     equ 0x0000
STAGE2_LOAD_OFF     equ 0x7E00
STAGE2_SECTORS      equ 12
STAGE2_START_SECTOR equ 2
SANDBOX_SEG         equ 0x0000
SANDBOX_OFF         equ 0x9000
SANDBOX_SECTORS     equ 8
SANDBOX_START_SEC   equ 14
SHELLCODE_SEG       equ 0x0000
SHELLCODE_OFF       equ 0xA000
SHELLCODE_SECTORS   equ 4
SHELLCODE_START_SEC equ 22
DISK_RETRY_COUNT    equ 5
VGA_TEXT_MEM        equ 0xB800
COLOR_HEADER        equ 0x0F
COLOR_INFO          equ 0x0A
COLOR_WARN          equ 0x0E
COLOR_ERROR         equ 0x0C
COLOR_DIM           equ 0x08
SCREEN_COLS         equ 80

jmp short _boot_entry
nop

db "SXLOADER"
dw 512
db 1
dw 1
db 2
dw 224
dw 2880
db 0xF0
dw 9
dw 18
dw 2
dd 0
dd 0
db 0x80
db 0
db 0x29
dd 0xDEADBEEF
db "SXSANDBOX  "
db "FAT12   "

_boot_entry:
    cli
    xor     ax, ax
    mov     ds, ax
    mov     es, ax
    mov     ss, ax
    mov     sp, 0x7BFC
    sti

    mov     [boot_drive], dl

    mov     ax, 0x0003
    int     0x10

    mov     ah, 0x01
    mov     cx, 0x2607
    int     0x10

    call    _draw_banner
    call    _draw_layout

    mov     byte [load_phase], 0
    mov     si, str_loading_stage2
    mov     bl, COLOR_INFO
    call    _status_print

    mov     ax, STAGE2_LOAD_SEG
    mov     es, ax
    mov     bx, STAGE2_LOAD_OFF
    mov     cx, STAGE2_SECTORS
    mov     dx, STAGE2_START_SECTOR
    call    _load_sectors
    jc      _fatal_disk_error

    mov     byte [load_phase], 1
    mov     si, str_loading_sandbox
    mov     bl, COLOR_INFO
    call    _status_print

    mov     ax, SANDBOX_SEG
    mov     es, ax
    mov     bx, SANDBOX_OFF
    mov     cx, SANDBOX_SECTORS
    mov     dx, SANDBOX_START_SEC
    call    _load_sectors
    jc      _fatal_disk_error

    mov     byte [load_phase], 2
    mov     si, str_loading_shell
    mov     bl, COLOR_INFO
    call    _status_print

    mov     ax, SHELLCODE_SEG
    mov     es, ax
    mov     bx, SHELLCODE_OFF
    mov     cx, SHELLCODE_SECTORS
    mov     dx, SHELLCODE_START_SEC
    call    _load_sectors
    jc      _fatal_disk_error

    mov     si, str_launch
    mov     bl, COLOR_HEADER
    call    _status_print

    call    _progress_animate

    xor     ax, ax
    mov     es, ax
    mov     dl, [boot_drive]

    jmp     STAGE2_LOAD_SEG:STAGE2_LOAD_OFF

_load_sectors:
    push    bp
    mov     bp, sp
    push    cx
    push    dx
    push    bx
    push    es

    mov     [.target_seg], es
    mov     [.target_off], bx
    mov     [.sector_count], cx
    mov     [.lba], dx

    mov     cx, [.sector_count]
    mov     ax, [.lba]

.next_sector:
    push    cx
    call    _lba_to_chs
    mov     cx, DISK_RETRY_COUNT

.retry:
    push    cx
    mov     ax, [.target_seg]
    mov     es, ax
    mov     bx, [.target_off]
    mov     ax, 0x0201
    mov     cx, [.chs_cylinder]
    mov     dh, [.chs_head]
    mov     dl, [boot_drive]
    int     0x13
    pop     cx
    jnc     .sector_ok
    pusha
    xor     ax, ax
    mov     dl, [boot_drive]
    int     0x13
    popa
    loop    .retry
    stc
    pop     cx
    jmp     .done

.sector_ok:
    mov     ax, [.target_off]
    add     ax, 512
    mov     [.target_off], ax
    jnc     .no_seg_update
    mov     ax, [.target_seg]
    add     ax, 0x1000
    mov     [.target_seg], ax

.no_seg_update:
    mov     ax, [.lba]
    inc     ax
    mov     [.lba], ax
    pop     cx
    loop    .next_sector
    clc

.done:
    pop     es
    pop     bx
    pop     dx
    pop     cx
    pop     bp
    ret

.target_seg     dw 0
.target_off     dw 0
.sector_count   dw 0
.lba            dw 0
.chs_cylinder   dw 0
.chs_head       db 0

_lba_to_chs:
    mov     ax, [.lba]
    xor     dx, dx
    div     word [sectors_per_track]
    mov     byte [_load_sectors.chs_head + 1], dl
    inc     byte [_load_sectors.chs_head + 1]
    xor     dx, dx
    div     word [num_heads]
    mov     byte [_load_sectors.chs_head], dl
    mov     cl, ah
    and     cl, 0x3F
    shl     ah, 6
    or      ah, cl
    mov     [_load_sectors.chs_cylinder], ax
    ret

sectors_per_track   dw 18
num_heads           dw 2

_draw_banner:
    pusha
    push    es
    mov     ax, VGA_TEXT_MEM
    mov     es, ax

    xor     di, di
    mov     cx, 80 * 25
    mov     ax, 0x0000 | (0x00 << 8)
    mov     ah, 0x01
    rep     stosw

    mov     di, (0 * 80 + 0) * 2
    mov     cx, 80
    mov     ax, (0x40 << 8) | 0xDC
    rep     stosw

    mov     si, str_banner_title
    mov     di, (0 * 80 + 2) * 2
    mov     ah, 0x4F
    call    _vga_print_at

    mov     si, str_banner_sub
    mov     di, (0 * 80 + 44) * 2
    mov     ah, 0x48
    call    _vga_print_at

    mov     di, (2 * 80 + 0) * 2
    mov     cx, 80
    mov     ax, (0x08 << 8) | 0xC4
    rep     stosw

    mov     si, str_section_loader
    mov     di, (4 * 80 + 2) * 2
    mov     ah, COLOR_HEADER
    call    _vga_print_at

    mov     si, str_section_status
    mov     di, (4 * 80 + 42) * 2
    mov     ah, COLOR_HEADER
    call    _vga_print_at

    mov     di, (3 * 80 + 0) * 2
    mov     cx, 80
    mov     ax, (0x08 << 8) | 0x20
    rep     stosw

    pop     es
    popa
    ret

_draw_layout:
    pusha
    push    es
    mov     ax, VGA_TEXT_MEM
    mov     es, ax

    mov     cx, 18
    mov     bx, 6

.draw_row:
    mov     di, bx
    imul    di, di, 80
    add     di, 0
    shl     di, 1
    mov     ax, (0x08 << 8) | 0xB3
    stosw
    mov     di, bx
    imul    di, di, 80
    add     di, 40
    shl     di, 1
    mov     ax, (0x08 << 8) | 0xB3
    stosw
    inc     bx
    loop    .draw_row

    mov     di, (6 * 80 + 1) * 2
    mov     cx, 38
    mov     ax, (0x08 << 8) | 0xC4
    rep     stosw

    mov     di, (6 * 80 + 41) * 2
    mov     cx, 38
    rep     stosw

    pop     es
    popa
    ret

_vga_print_at:
    push    es
    push    ax
    push    di
    push    si
    mov     bx, ax

.loop:
    lodsb
    test    al, al
    jz      .done
    mov     ah, bh
    stosw
    jmp     .loop

.done:
    pop     si
    pop     di
    pop     ax
    pop     es
    ret

_status_print:
    pusha
    push    es

    mov     ax, VGA_TEXT_MEM
    mov     es, ax

    mov     al, [status_row]
    mov     ah, 0
    imul    ax, ax, 80
    add     ax, 42
    shl     ax, 1
    mov     di, ax
    mov     ah, bl

.loop:
    lodsb
    test    al, al
    jz      .done
    stosw
    jmp     .loop

.done:
    inc     byte [status_row]

    pop     es
    popa
    ret

_progress_animate:
    pusha
    push    es

    mov     ax, VGA_TEXT_MEM
    mov     es, ax

    mov     si, str_progress_label
    mov     di, (22 * 80 + 2) * 2
    mov     ah, COLOR_DIM
    call    _vga_print_at

    mov     cx, 50
    mov     bx, (22 * 80 + 18) * 2

.bar_loop:
    push    cx
    push    bx

    mov     di, bx
    mov     ax, (0x0A << 8) | 0xDB
    stosw

    mov     cx, 0x2FFF
.delay:
    loop    .delay

    pop     bx
    pop     cx
    add     bx, 2
    loop    .bar_loop

    pop     es
    popa
    ret

_fatal_disk_error:
    push    es
    mov     ax, VGA_TEXT_MEM
    mov     es, ax

    mov     si, str_disk_error
    mov     di, (23 * 80 + 2) * 2
    mov     ah, COLOR_ERROR
    call    _vga_print_at

    mov     si, str_halt_msg
    mov     di, (24 * 80 + 2) * 2
    mov     ah, COLOR_WARN
    call    _vga_print_at

    pop     es

.freeze:
    cli
    hlt
    jmp     .freeze

boot_drive      db 0
load_phase      db 0
status_row      db 7

str_banner_title    db "  SX-SANDBOX  SHELLCODE EXECUTION ENVIRONMENT  v1.2", 0
str_banner_sub      db "x86 BARE-METAL", 0
str_section_loader  db "[ LOADER SUBSYSTEM ]", 0
str_section_status  db "[ BOOT STATUS ]", 0
str_loading_stage2  db "[*] Initializing execution engine...", 0
str_loading_sandbox db "[*] Loading sandbox protection layer...", 0
str_loading_shell   db "[*] Staging shellcode payloads...", 0
str_launch          db "[+] All modules verified. Launching...", 0
str_progress_label  db "LOADING  [", 0
str_disk_error      db "[!] FATAL: Disk read failure. Sector unreadable.", 0
str_halt_msg        db "    System halted. Press RESET to restart.", 0

times 510 - ($ - $$) db 0
dw 0xAA55
