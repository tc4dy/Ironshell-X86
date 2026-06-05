BITS 16
ORG 0x7E00

SANDBOX_ENTRY       equ 0x9000
SHELLCODE_BASE      equ 0xA000
MAX_PAYLOAD_COUNT   equ 8
INPUT_BUFFER_SIZE   equ 128
HISTORY_DEPTH       equ 8
HISTORY_ENTRY_SIZE  equ 64
VGA_TEXT_MEM        equ 0xB800
SCREEN_ROWS         equ 25
SCREEN_COLS         equ 80
LOG_START_ROW       equ 8
LOG_VISIBLE_ROWS    equ 13
STATUS_BAR_ROW      equ 24
TITLE_ROW           equ 0
COLOR_NORMAL        equ 0x07
COLOR_BRIGHT        equ 0x0F
COLOR_SUCCESS       equ 0x0A
COLOR_ERROR         equ 0x0C
COLOR_WARN          equ 0x0E
COLOR_ACCENT        equ 0x0B
COLOR_DIM           equ 0x08
COLOR_HIGHLIGHT     equ 0x70
COLOR_SELECTED      equ 0x2F
VGA_WIDTH_BYTES     equ 160

stage2_main:
    xor     ax, ax
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax
    mov     sp, 0x7BFC

    mov     [engine_drive], dl

    call    _init_payload_table
    call    _ui_full_redraw
    call    _run_sandbox_checks
    call    _shell_loop

    cli
    hlt
    jmp     $

_init_payload_table:
    pusha
    mov     di, payload_table
    mov     cx, MAX_PAYLOAD_COUNT * 32
    xor     al, al
    rep     stosb

    mov     word [payload_count], 0
    mov     word [selected_payload], 0
    mov     word [log_scroll], 0
    mov     word [history_head], 0
    mov     word [history_count], 0

    mov     si, str_payload_msgbox
    mov     di, payload_table + 0 * 32
    call    _strcpy_16
    mov     byte [payload_flags + 0], 0x01

    mov     si, str_payload_memwalk
    mov     di, payload_table + 1 * 32
    call    _strcpy_16
    mov     byte [payload_flags + 1], 0x01

    mov     si, str_payload_portprobe
    mov     di, payload_table + 2 * 32
    call    _strcpy_16
    mov     byte [payload_flags + 2], 0x01

    mov     si, str_payload_stacksmash
    mov     di, payload_table + 3 * 32
    call    _strcpy_16
    mov     byte [payload_flags + 3], 0x02

    mov     si, str_payload_nxprobe
    mov     di, payload_table + 4 * 32
    call    _strcpy_16
    mov     byte [payload_flags + 4], 0x01

    mov     si, str_payload_cpuinfo
    mov     di, payload_table + 5 * 32
    call    _strcpy_16
    mov     byte [payload_flags + 5], 0x01

    mov     word [payload_count], 6
    popa
    ret

_run_sandbox_checks:
    call    _log_separator
    mov     si, str_sandbox_init
    call    _log_line_accent

    call    _check_nx_bit
    call    _check_smep
    call    _check_cpuid_features
    call    _check_memory_size
    call    _check_a20

    call    _log_separator
    ret

_check_nx_bit:
    pusha
    mov     eax, 0x80000001
    cpuid
    test    edx, (1 << 20)
    jz      .no_nx
    mov     si, str_nx_enabled
    mov     bl, COLOR_WARN
    call    _log_line_colored
    mov     byte [nx_active], 1
    jmp     .done
.no_nx:
    mov     si, str_nx_disabled
    mov     bl, COLOR_SUCCESS
    call    _log_line_colored
    mov     byte [nx_active], 0
.done:
    popa
    ret

_check_smep:
    pusha
    mov     eax, 7
    xor     ecx, ecx
    cpuid
    test    ebx, (1 << 7)
    jz      .no_smep
    mov     si, str_smep_on
    mov     bl, COLOR_WARN
    call    _log_line_colored
    mov     byte [smep_active], 1
    jmp     .done
.no_smep:
    mov     si, str_smep_off
    mov     bl, COLOR_SUCCESS
    call    _log_line_colored
    mov     byte [smep_active], 0
.done:
    popa
    ret

_check_cpuid_features:
    pusha
    mov     eax, 1
    cpuid
    mov     [cpuid_edx_feat], edx
    mov     [cpuid_ecx_feat], ecx

    mov     si, str_cpuid_vendor
    mov     bl, COLOR_ACCENT
    call    _log_line_colored

    push    es
    xor     ax, ax
    mov     es, ax
    mov     eax, 0
    cpuid
    mov     [cpu_vendor_buf],     ebx
    mov     [cpu_vendor_buf + 4], edx
    mov     [cpu_vendor_buf + 8], ecx
    mov     byte [cpu_vendor_buf + 12], 0
    pop     es

    mov     si, str_prefix_vendor
    call    _log_partial
    mov     si, cpu_vendor_buf
    mov     bl, COLOR_BRIGHT
    call    _log_line_colored
    popa
    ret

_check_memory_size:
    pusha
    int     0x12
    mov     [conv_mem_kb], ax
    mov     si, str_prefix_memory
    call    _log_partial
    mov     ax, [conv_mem_kb]
    call    _log_decimal_kb
    popa
    ret

_check_a20:
    pusha
    call    _test_a20_gate
    jc      .enabled
    mov     si, str_a20_off
    mov     bl, COLOR_ERROR
    call    _log_line_colored
    jmp     .done
.enabled:
    mov     si, str_a20_on
    mov     bl, COLOR_SUCCESS
    call    _log_line_colored
.done:
    popa
    ret

_test_a20_gate:
    push    es
    push    di
    push    si
    mov     ax, 0xFFFF
    mov     es, ax
    mov     di, 0x0510
    mov     si, 0x0500
    mov     al, [si]
    push    ax
    mov     al, [es:di]
    push    ax
    mov     byte [si],    0x00
    mov     byte [es:di], 0xFF
    cmp     byte [si], 0xFF
    pop     ax
    mov     [es:di], al
    pop     ax
    mov     [si], al
    pop     si
    pop     di
    pop     es
    jne     .a20_on
    clc
    ret
.a20_on:
    stc
    ret

_shell_loop:
    call    _ui_draw_prompt
.main:
    mov     di, input_buffer
    mov     word [input_len], 0
    call    _readline
    call    _dispatch_command
    jmp     .main

_readline:
    pusha
    xor     cx, cx
    mov     di, input_buffer

.key:
    xor     ah, ah
    int     0x16

    cmp     al, 0x0D
    je      .enter

    cmp     al, 0x08
    je      .backspace

    cmp     al, 0
    je      .special_key

    cmp     cx, INPUT_BUFFER_SIZE - 1
    jge     .key

    stosb
    inc     cx
    call    _echo_char
    jmp     .key

.special_key:
    cmp     ah, 0x48
    je      .hist_up
    cmp     ah, 0x50
    je      .hist_down
    jmp     .key

.hist_up:
    call    _history_prev
    jmp     .key

.hist_down:
    call    _history_next
    jmp     .key

.backspace:
    test    cx, cx
    jz      .key
    dec     di
    dec     cx
    call    _echo_backspace
    jmp     .key

.enter:
    mov     byte [di], 0
    mov     [input_len], cx
    call    _newline_echo
    cmp     cx, 0
    jz      .skip_history
    call    _history_push
.skip_history:
    popa
    ret

_dispatch_command:
    pusha
    mov     si, input_buffer
    cmp     byte [si], 0
    je      .done

    mov     di, cmd_run
    call    _strcmp_ci
    jz      .do_run

    mov     di, cmd_list
    call    _strcmp_ci
    jz      .do_list

    mov     di, cmd_info
    call    _strcmp_ci
    jz      .do_info

    mov     di, cmd_clear
    call    _strcmp_ci
    jz      .do_clear

    mov     di, cmd_help
    call    _strcmp_ci
    jz      .do_help

    mov     di, cmd_sel
    call    _strcmp_prefix
    jz      .do_select

    mov     di, cmd_sandbox
    call    _strcmp_ci
    jz      .do_sandbox

    mov     di, cmd_dump
    call    _strcmp_prefix
    jz      .do_dump

    mov     si, str_unknown_cmd
    call    _log_line_error
    jmp     .done

.do_run:
    call    _cmd_run_payload
    jmp     .done

.do_list:
    call    _cmd_list_payloads
    jmp     .done

.do_info:
    call    _cmd_show_info
    jmp     .done

.do_clear:
    call    _cmd_clear_log
    jmp     .done

.do_help:
    call    _cmd_show_help
    jmp     .done

.do_select:
    call    _cmd_select_payload
    jmp     .done

.do_sandbox:
    call    _run_sandbox_checks
    jmp     .done

.do_dump:
    call    _cmd_hexdump
    jmp     .done

.done:
    call    _ui_draw_prompt
    popa
    ret

_cmd_run_payload:
    pusha
    mov     ax, [selected_payload]
    cmp     ax, [payload_count]
    jge     .invalid

    call    _log_separator

    mov     si, str_exec_start
    call    _log_line_accent

    push    ax
    mov     si, str_prefix_exec
    call    _log_partial

    pop     ax
    push    ax
    mov     bx, 32
    mul     bx
    mov     si, ax
    add     si, payload_table
    mov     bl, COLOR_BRIGHT
    call    _log_line_colored

    pop     ax
    push    ax

    mov     bl, COLOR_DIM
    mov     si, str_sandbox_check
    call    _log_line_colored

    pop     ax
    call    _dispatch_payload

    call    _log_separator
    popa
    ret

.invalid:
    mov     si, str_no_payload
    call    _log_line_error
    popa
    ret

_dispatch_payload:
    cmp     ax, 0
    je      _payload_msgbox
    cmp     ax, 1
    je      _payload_memwalk
    cmp     ax, 2
    je      _payload_portprobe
    cmp     ax, 3
    je      _payload_stacksmash
    cmp     ax, 4
    je      _payload_nxprobe
    cmp     ax, 5
    je      _payload_cpuinfo
    ret

_payload_msgbox:
    pusha
    mov     si, str_pl_msgbox_1
    mov     bl, COLOR_SUCCESS
    call    _log_line_colored
    mov     si, str_pl_msgbox_2
    mov     bl, COLOR_NORMAL
    call    _log_line_colored

    push    es
    xor     ax, ax
    mov     es, ax
    mov     word [es:SHELLCODE_BASE],     0xB8C0
    mov     word [es:SHELLCODE_BASE + 2], 0x07C0
    mov     word [es:SHELLCODE_BASE + 4], 0x90C3
    pop     es

    mov     si, str_pl_injected
    mov     bl, COLOR_ACCENT
    call    _log_line_colored

    call    SHELLCODE_BASE

    mov     si, str_pl_returned
    mov     bl, COLOR_SUCCESS
    call    _log_line_colored
    popa
    ret

_payload_memwalk:
    pusha
    mov     si, str_pl_memwalk_1
    mov     bl, COLOR_SUCCESS
    call    _log_line_colored

    push    es
    xor     ax, ax
    mov     es, ax

    mov     cx, 8
    mov     bx, 0x0400

.walk_loop:
    mov     ax, [es:bx]
    push    cx
    push    bx

    mov     si, str_prefix_addr
    call    _log_partial
    mov     ax, bx
    call    _log_hex_word
    mov     si, str_colon_space
    call    _log_partial

    pop     bx
    mov     ax, [es:bx]
    call    _log_hex_word_newline

    add     bx, 2
    pop     cx
    loop    .walk_loop

    pop     es
    popa
    ret

_payload_portprobe:
    pusha
    mov     si, str_pl_port_1
    mov     bl, COLOR_SUCCESS
    call    _log_line_colored

    mov     cx, 8
    mov     dx, 0x03F8

.probe_loop:
    push    cx
    push    dx

    in      al, dx
    mov     bl, al

    mov     si, str_prefix_port
    call    _log_partial
    pop     dx
    push    dx
    mov     ax, dx
    call    _log_hex_word
    mov     si, str_arrow
    call    _log_partial
    mov     al, bl
    call    _log_hex_byte_newline

    pop     dx
    add     dx, 8
    pop     cx
    loop    .probe_loop

    popa
    ret

_payload_stacksmash:
    pusha
    mov     si, str_pl_stack_1
    mov     bl, COLOR_WARN
    call    _log_line_colored

    mov     ax, ss
    push    ax
    mov     si, str_prefix_ss
    call    _log_partial
    pop     ax
    call    _log_hex_word_newline

    mov     ax, sp
    push    ax
    mov     si, str_prefix_sp
    call    _log_partial
    pop     ax
    call    _log_hex_word_newline

    mov     si, str_pl_stack_2
    mov     bl, COLOR_WARN
    call    _log_line_colored

    mov     cx, 4
.probe_stack:
    push    word 0xDEAD
    loop    .probe_stack

    mov     cx, 4
.check_stack:
    pop     ax
    cmp     ax, 0xDEAD
    jne     .corrupt
    loop    .check_stack

    mov     si, str_pl_stack_ok
    mov     bl, COLOR_SUCCESS
    call    _log_line_colored
    popa
    ret

.corrupt:
    mov     si, str_pl_stack_corrupt
    call    _log_line_error
    popa
    ret

_payload_nxprobe:
    pusha
    mov     si, str_pl_nx_1
    mov     bl, COLOR_SUCCESS
    call    _log_line_colored

    cmp     byte [nx_active], 1
    je      .nx_on

    mov     si, str_pl_nx_exec
    mov     bl, COLOR_SUCCESS
    call    _log_line_colored

    push    es
    xor     ax, ax
    mov     es, ax
    mov     byte [es:SHELLCODE_BASE], 0xC3
    pop     es

    call    SHELLCODE_BASE

    mov     si, str_pl_nx_done
    mov     bl, COLOR_SUCCESS
    call    _log_line_colored
    popa
    ret

.nx_on:
    mov     si, str_pl_nx_blocked
    mov     bl, COLOR_WARN
    call    _log_line_colored
    popa
    ret

_payload_cpuinfo:
    pusha
    mov     si, str_pl_cpu_1
    mov     bl, COLOR_SUCCESS
    call    _log_line_colored

    mov     eax, 0x80000000
    cpuid
    cmp     eax, 0x80000004
    jb      .no_brand

    mov     eax, 0x80000002
    cpuid
    mov     [cpu_brand],      eax
    mov     [cpu_brand + 4],  ebx
    mov     [cpu_brand + 8],  ecx
    mov     [cpu_brand + 12], edx

    mov     eax, 0x80000003
    cpuid
    mov     [cpu_brand + 16], eax
    mov     [cpu_brand + 20], ebx
    mov     [cpu_brand + 24], ecx
    mov     [cpu_brand + 28], edx

    mov     eax, 0x80000004
    cpuid
    mov     [cpu_brand + 32], eax
    mov     [cpu_brand + 36], ebx
    mov     [cpu_brand + 40], ecx
    mov     [cpu_brand + 44], edx
    mov     byte [cpu_brand + 48], 0

    mov     si, str_prefix_brand
    call    _log_partial
    mov     si, cpu_brand
    mov     bl, COLOR_BRIGHT
    call    _log_line_colored
    jmp     .feat

.no_brand:
    mov     si, str_no_brand
    mov     bl, COLOR_DIM
    call    _log_line_colored

.feat:
    mov     eax, 1
    cpuid
    mov     si, str_prefix_stepping
    call    _log_partial
    and     eax, 0xF
    call    _log_decimal_newline

    mov     edx, [cpuid_edx_feat]
    test    edx, (1 << 25)
    jz      .no_sse
    mov     si, str_feat_sse
    mov     bl, COLOR_SUCCESS
    call    _log_line_colored
.no_sse:
    test    edx, (1 << 26)
    jz      .no_sse2
    mov     si, str_feat_sse2
    mov     bl, COLOR_SUCCESS
    call    _log_line_colored
.no_sse2:
    mov     ecx, [cpuid_ecx_feat]
    test    ecx, (1 << 28)
    jz      .no_avx
    mov     si, str_feat_avx
    mov     bl, COLOR_SUCCESS
    call    _log_line_colored
.no_avx:
    popa
    ret

_cmd_list_payloads:
    pusha
    call    _log_separator
    mov     si, str_list_header
    call    _log_line_accent

    xor     cx, cx
.loop:
    cmp     cx, [payload_count]
    jge     .done

    push    cx
    cmp     cx, [selected_payload]
    jne     .not_selected

    mov     si, str_list_sel_prefix
    mov     bl, COLOR_SELECTED
    call    _log_partial_colored
    jmp     .print_name

.not_selected:
    mov     si, str_list_prefix
    mov     bl, COLOR_DIM
    call    _log_partial_colored

.print_name:
    pop     cx
    push    cx

    mov     ax, cx
    mov     bx, 32
    mul     bx
    mov     si, ax
    add     si, payload_table

    mov     bl, COLOR_NORMAL
    cmp     byte [payload_flags + cx], 0x02
    jne     .safe_flag
    mov     bl, COLOR_WARN

.safe_flag:
    call    _log_line_colored

    pop     cx
    inc     cx
    jmp     .loop

.done:
    call    _log_separator
    popa
    ret

_cmd_show_info:
    pusha
    call    _log_separator
    mov     si, str_info_header
    call    _log_line_accent

    mov     si, str_info_1
    mov     bl, COLOR_NORMAL
    call    _log_line_colored
    mov     si, str_info_2
    call    _log_line_colored
    mov     si, str_info_3
    call    _log_line_colored
    mov     si, str_info_4
    call    _log_line_colored

    call    _log_separator
    popa
    ret

_cmd_clear_log:
    pusha
    mov     word [log_line_count], 0
    mov     word [log_scroll], 0
    call    _ui_redraw_log
    popa
    ret

_cmd_show_help:
    pusha
    call    _log_separator
    mov     si, str_help_header
    call    _log_line_accent
    mov     si, str_help_run
    mov     bl, COLOR_NORMAL
    call    _log_line_colored
    mov     si, str_help_list
    call    _log_line_colored
    mov     si, str_help_sel
    call    _log_line_colored
    mov     si, str_help_sandbox
    call    _log_line_colored
    mov     si, str_help_dump
    call    _log_line_colored
    mov     si, str_help_info
    call    _log_line_colored
    mov     si, str_help_clear
    call    _log_line_colored
    call    _log_separator
    popa
    ret

_cmd_select_payload:
    pusha
    mov     si, input_buffer + 4
    call    _skip_spaces
    call    _parse_decimal
    jc      .bad
    cmp     ax, [payload_count]
    jge     .oob
    mov     [selected_payload], ax
    mov     si, str_sel_ok
    call    _log_line_accent
    popa
    ret
.bad:
    mov     si, str_sel_bad
    call    _log_line_error
    popa
    ret
.oob:
    mov     si, str_sel_oob
    call    _log_line_error
    popa
    ret

_cmd_hexdump:
    pusha
    mov     si, input_buffer + 5
    call    _skip_spaces
    call    _parse_hex_word
    jc      .bad
    mov     bx, ax

    push    es
    xor     ax, ax
    mov     es, ax

    mov     cx, 4
.row:
    push    cx
    push    bx

    mov     ax, bx
    call    _log_hex_word
    mov     si, str_colon_space
    call    _log_partial

    mov     cx, 8
.byte_loop:
    mov     al, [es:bx]
    call    _log_hex_byte_space
    inc     bx
    loop    .byte_loop

    call    _newline_log

    pop     bx
    add     bx, 8
    pop     cx
    loop    .row

    pop     es
    popa
    ret

.bad:
    mov     si, str_dump_bad
    call    _log_line_error
    popa
    ret

_ui_full_redraw:
    call    _ui_draw_static_frame
    call    _ui_redraw_payload_list
    call    _ui_redraw_log
    call    _ui_draw_prompt
    call    _ui_draw_statusbar
    ret

_ui_draw_static_frame:
    pusha
    push    es
    mov     ax, VGA_TEXT_MEM
    mov     es, ax

    xor     di, di
    mov     cx, SCREEN_ROWS * SCREEN_COLS
    mov     ax, (0x01 << 8) | 0x20
    rep     stosw

    mov     di, TITLE_ROW * VGA_WIDTH_BYTES
    mov     cx, SCREEN_COLS
    mov     ax, (0x40 << 8) | 0x20
    rep     stosw

    mov     di, TITLE_ROW * VGA_WIDTH_BYTES
    mov     ah, 0x4F
    mov     si, str_title_bar
    call    _vga_str_es

    mov     di, (TITLE_ROW * 80 + 60) * 2
    mov     si, str_title_right
    mov     ah, 0x4B
    call    _vga_str_es

    mov     di, 2 * VGA_WIDTH_BYTES
    mov     cx, SCREEN_COLS
    mov     ax, (0x08 << 8) | 0xCD
    rep     stosw

    mov     di, 2 * VGA_WIDTH_BYTES
    mov     ax, (0x08 << 8) | 0xC9
    stosw
    mov     di, (2 * 80 + 79) * 2
    mov     ax, (0x08 << 8) | 0xBB
    stosw

    mov     di, 3 * VGA_WIDTH_BYTES
    mov     cx, SCREEN_COLS
    mov     ax, (0x08 << 8) | 0x20
    rep     stosw

    mov     di, (3 * 80 + 1) * 2
    mov     ah, 0x0B
    mov     si, str_subtitle
    call    _vga_str_es

    mov     di, 4 * VGA_WIDTH_BYTES
    mov     cx, SCREEN_COLS
    mov     ax, (0x08 << 8) | 0xC4
    rep     stosw

    mov     di, (4 * 80 + 0) * 2
    mov     ax, (0x08 << 8) | 0xC7
    stosw
    mov     di, (4 * 80 + 79) * 2
    mov     ax, (0x08 << 8) | 0xB6
    stosw

    mov     bx, 5
.border_rows:
    cmp     bx, 23
    jge     .border_done
    mov     di, bx
    imul    di, di, 80
    shl     di, 1

    mov     ax, (0x08 << 8) | 0xB3
    stosw

    mov     di, bx
    imul    di, di, 80
    add     di, 24
    shl     di, 1
    stosw

    mov     di, bx
    imul    di, di, 80
    add     di, 25
    shl     di, 1
    mov     ax, (0x08 << 8) | 0xB3
    stosw

    mov     di, bx
    imul    di, di, 80
    add     di, 79
    shl     di, 1
    stosw

    inc     bx
    jmp     .border_rows
.border_done:

    mov     di, (5 * 80 + 1) * 2
    mov     ah, 0x08
    mov     si, str_panel_payloads
    call    _vga_str_es

    mov     di, (5 * 80 + 26) * 2
    mov     si, str_panel_log
    call    _vga_str_es

    mov     di, 23 * VGA_WIDTH_BYTES
    mov     cx, SCREEN_COLS
    mov     ax, (0x08 << 8) | 0xC4
    rep     stosw

    mov     di, (23 * 80 + 0) * 2
    mov     ax, (0x08 << 8) | 0xC0
    stosw
    mov     di, (23 * 80 + 24) * 2
    mov     ax, (0x08 << 8) | 0xC1
    stosw
    mov     di, (23 * 80 + 79) * 2
    mov     ax, (0x08 << 8) | 0xD9
    stosw

    pop     es
    popa
    ret

_ui_draw_statusbar:
    pusha
    push    es
    mov     ax, VGA_TEXT_MEM
    mov     es, ax

    mov     di, STATUS_BAR_ROW * VGA_WIDTH_BYTES
    mov     cx, SCREEN_COLS
    mov     ax, (0x30 << 8) | 0x20
    rep     stosw

    mov     di, STATUS_BAR_ROW * VGA_WIDTH_BYTES
    mov     si, str_status_bar
    mov     ah, 0x30
    call    _vga_str_es

    pop     es
    popa
    ret

_ui_redraw_payload_list:
    pusha
    push    es
    mov     ax, VGA_TEXT_MEM
    mov     es, ax

    mov     bx, 6
.clear_row:
    cmp     bx, 23
    jge     .clear_done
    mov     di, bx
    imul    di, di, 80
    add     di, 1
    shl     di, 1
    mov     cx, 23
    mov     ax, (0x01 << 8) | 0x20
    rep     stosw
    inc     bx
    jmp     .clear_row
.clear_done:

    xor     cx, cx
    mov     bx, 6

.list_loop:
    cmp     cx, [payload_count]
    jge     .list_done
    cmp     bx, 23
    jge     .list_done

    mov     di, bx
    imul    di, di, 80
    add     di, 1
    shl     di, 1

    cmp     cx, [selected_payload]
    jne     .not_sel

    push    di
    mov     ax, (0x2F << 8) | 0x10
    stosw
    mov     ax, (0x2F << 8) | 0x10
    stosw
    pop     di
    add     di, 4
    mov     ah, 0x2F
    jmp     .print_entry

.not_sel:
    add     di, 4
    mov     ah, 0x07

.print_entry:
    push    cx
    mov     ax, cx
    mov     bx, 32
    mul     bx
    mov     si, payload_table
    add     si, ax

    cmp     byte [payload_flags + cx], 0x02
    jne     .not_danger
    mov     ah, 0x0E

.not_danger:
    call    _vga_str_es
    pop     cx
    inc     cx

    mov     bx, 6
    add     bx, cx
    jmp     .list_loop

.list_done:
    pop     es
    popa
    ret

_ui_redraw_log:
    pusha
    push    es
    mov     ax, VGA_TEXT_MEM
    mov     es, ax

    mov     bx, 6
.clear:
    cmp     bx, 23
    jge     .clear_done
    mov     di, bx
    imul    di, di, 80
    add     di, 26
    shl     di, 1
    mov     cx, 53
    mov     ax, (0x01 << 8) | 0x20
    rep     stosw
    inc     bx
    jmp     .clear
.clear_done:

    mov     ax, [log_line_count]
    sub     ax, LOG_VISIBLE_ROWS
    jge     .scroll_ok
    xor     ax, ax
.scroll_ok:
    add     ax, [log_scroll]
    mov     cx, ax
    mov     bx, 6

.render_loop:
    cmp     bx, 23
    jge     .render_done

    push    bx
    push    cx
    mov     ax, cx
    mov     bx, LOG_LINE_WIDTH
    mul     bx
    mov     si, log_buffer
    add     si, ax

    mov     di, sp
    add     di, 4
    pop     cx
    pop     bx

    push    bx
    push    cx
    mov     ax, bx
    imul    ax, ax, 80
    add     ax, 26
    shl     ax, 1
    mov     di, ax

    mov     ax, cx
    mov     bx, LOG_LINE_WIDTH
    mul     bx
    mov     si, log_buffer
    add     si, ax

    mov     ax, cx
    mov     bx, LOG_COLOR_WIDTH
    mul     bx
    mov     ah, [log_colors + ax]

    call    _vga_str_es
    pop     cx
    pop     bx

    inc     cx
    inc     bx
    cmp     cx, [log_line_count]
    jl      .render_loop

.render_done:
    pop     es
    popa
    ret

_ui_draw_prompt:
    pusha
    push    es
    mov     ax, VGA_TEXT_MEM
    mov     es, ax

    mov     di, (STATUS_BAR_ROW - 1) * VGA_WIDTH_BYTES
    mov     cx, SCREEN_COLS
    mov     ax, (0x08 << 8) | 0x20
    rep     stosw

    mov     di, (STATUS_BAR_ROW - 1) * VGA_WIDTH_BYTES
    mov     si, str_prompt
    mov     ah, 0x0A
    call    _vga_str_es

    mov     ax, VGA_TEXT_MEM >> 4
    mov     bh, 0
    mov     ah, 0x02
    mov     dh, STATUS_BAR_ROW - 1
    mov     dl, 9
    int     0x10

    pop     es
    popa
    ret

_log_line_colored:
    pusha
    call    _log_add_line
    mov     [log_color_temp], bl
    dec     word [log_line_count]
    mov     ax, [log_line_count]
    mov     [log_colors + ax], bl
    inc     word [log_line_count]
    call    _ui_redraw_log
    popa
    ret

_log_line_accent:
    mov     bl, COLOR_ACCENT
    call    _log_line_colored
    ret

_log_line_error:
    mov     bl, COLOR_ERROR
    call    _log_line_colored
    ret

_log_separator:
    pusha
    mov     si, str_separator
    mov     bl, COLOR_DIM
    call    _log_line_colored
    popa
    ret

_log_add_line:
    pusha
    mov     ax, [log_line_count]
    cmp     ax, LOG_MAX_LINES
    jl      .ok
    call    _log_scroll_up
    mov     ax, [log_line_count]
.ok:
    mov     bx, LOG_LINE_WIDTH
    mul     bx
    mov     di, log_buffer
    add     di, ax

    mov     cx, LOG_LINE_WIDTH - 1
.copy:
    lodsb
    test    al, al
    jz      .pad
    stosb
    loop    .copy
    jmp     .done
.pad:
    mov     al, 0x20
    rep     stosb
.done:
    mov     byte [di], 0
    inc     word [log_line_count]
    popa
    ret

_log_scroll_up:
    pusha
    mov     si, log_buffer + LOG_LINE_WIDTH
    mov     di, log_buffer
    mov     cx, (LOG_MAX_LINES - 1) * LOG_LINE_WIDTH
    rep     movsb

    mov     si, log_colors + 1
    mov     di, log_colors
    mov     cx, LOG_MAX_LINES - 1
    rep     movsb

    dec     word [log_line_count]
    popa
    ret

_log_partial:
    pusha
    mov     ax, [log_line_count]
    mov     bx, LOG_LINE_WIDTH
    mul     bx
    mov     di, log_buffer
    add     di, ax
    mov     cx, [partial_offset]
    add     di, cx
.copy:
    lodsb
    test    al, al
    jz      .done
    stosb
    inc     word [partial_offset]
    jmp     .copy
.done:
    popa
    ret

_log_partial_colored:
    ret

_newline_log:
    pusha
    mov     word [partial_offset], 0
    inc     word [log_line_count]
    cmp     word [log_line_count], LOG_MAX_LINES
    jl      .ok
    call    _log_scroll_up
.ok:
    call    _ui_redraw_log
    popa
    ret

_log_hex_word:
    pusha
    push    ax
    mov     cl, 12
    shr     ax, cl
    call    _nibble_char
    pop     ax
    push    ax
    mov     cl, 8
    shr     ax, cl
    and     al, 0xF
    call    _nibble_char
    pop     ax
    push    ax
    mov     cl, 4
    shr     ax, cl
    and     al, 0xF
    call    _nibble_char
    pop     ax
    and     al, 0xF
    call    _nibble_char
    popa
    ret

_log_hex_word_newline:
    call    _log_hex_word
    call    _newline_log
    ret

_log_hex_byte_newline:
    push    ax
    shr     al, 4
    call    _nibble_char
    pop     ax
    and     al, 0xF
    call    _nibble_char
    call    _newline_log
    ret

_log_hex_byte_space:
    push    ax
    push    si
    push    ax
    shr     al, 4
    call    _nibble_char
    pop     ax
    and     al, 0xF
    call    _nibble_char
    mov     si, str_space
    call    _log_partial
    pop     si
    pop     ax
    ret

_log_decimal_kb:
    pusha
    call    _decimal_to_str
    mov     si, decimal_buf
    call    _log_partial
    mov     si, str_kb_suffix
    mov     bl, COLOR_DIM
    call    _log_line_colored
    popa
    ret

_log_decimal_newline:
    pusha
    call    _decimal_to_str
    mov     si, decimal_buf
    call    _log_partial
    call    _newline_log
    popa
    ret

_nibble_char:
    push    si
    push    ax
    and     al, 0xF
    cmp     al, 9
    jbe     .digit
    add     al, 7
.digit:
    add     al, 0x30
    mov     [nibble_tmp], al
    mov     si, nibble_tmp
    call    _log_partial
    pop     ax
    pop     si
    ret

_decimal_to_str:
    pusha
    mov     di, decimal_buf + 9
    mov     byte [di], 0
    mov     bx, 10
    test    ax, ax
    jnz     .divide
    dec     di
    mov     byte [di], '0'
    jmp     .done
.divide:
    test    ax, ax
    jz      .done
    xor     dx, dx
    div     bx
    add     dl, '0'
    dec     di
    mov     [di], dl
    jmp     .divide
.done:
    popa
    ret

_echo_char:
    push    ax
    push    bx
    mov     ah, 0x0E
    mov     bx, 0x0007
    int     0x10
    pop     bx
    pop     ax
    ret

_echo_backspace:
    pusha
    mov     ah, 0x0E
    mov     al, 0x08
    int     0x10
    mov     al, 0x20
    int     0x10
    mov     al, 0x08
    int     0x10
    popa
    ret

_newline_echo:
    pusha
    mov     ah, 0x0E
    mov     al, 0x0D
    int     0x10
    mov     al, 0x0A
    int     0x10
    popa
    ret

_history_push:
    pusha
    mov     ax, [history_head]
    mov     bx, HISTORY_ENTRY_SIZE
    mul     bx
    mov     di, history_buffer
    add     di, ax
    mov     si, input_buffer
    mov     cx, HISTORY_ENTRY_SIZE - 1
    rep     movsb
    mov     byte [di], 0
    inc     word [history_head]
    mov     ax, [history_head]
    cmp     ax, HISTORY_DEPTH
    jl      .ok
    mov     word [history_head], 0
.ok:
    mov     ax, [history_count]
    cmp     ax, HISTORY_DEPTH
    jge     .max
    inc     word [history_count]
.max:
    mov     ax, [history_head]
    mov     [history_cursor], ax
    popa
    ret

_history_prev:
    ret

_history_next:
    ret

_strcmp_ci:
    push    si
    push    di
.loop:
    mov     al, [si]
    mov     bl, [di]
    call    _to_upper_al
    push    ax
    mov     al, bl
    call    _to_upper_al
    mov     bl, al
    pop     ax
    cmp     al, bl
    jne     .ne
    test    al, al
    jz      .eq
    inc     si
    inc     di
    jmp     .loop
.eq:
    pop     di
    pop     si
    xor     ax, ax
    ret
.ne:
    pop     di
    pop     si
    or      ax, 1
    ret

_strcmp_prefix:
    push    si
    push    di
.loop:
    mov     bl, [di]
    test    bl, bl
    jz      .match
    mov     al, [si]
    call    _to_upper_al
    push    ax
    mov     al, bl
    call    _to_upper_al
    mov     bl, al
    pop     ax
    cmp     al, bl
    jne     .ne
    inc     si
    inc     di
    jmp     .loop
.match:
    pop     di
    pop     si
    xor     ax, ax
    ret
.ne:
    pop     di
    pop     si
    or      ax, 1
    ret

_to_upper_al:
    cmp     al, 'a'
    jb      .done
    cmp     al, 'z'
    ja      .done
    sub     al, 0x20
.done:
    ret

_strcpy_16:
    push    si
    push    di
    mov     cx, 31
.loop:
    lodsb
    stosb
    test    al, al
    jz      .done
    loop    .loop
.done:
    mov     byte [di], 0
    pop     di
    pop     si
    ret

_skip_spaces:
.loop:
    cmp     byte [si], 0x20
    jne     .done
    inc     si
    jmp     .loop
.done:
    ret

_parse_decimal:
    push    si
    xor     ax, ax
    mov     cx, 0
.loop:
    mov     bl, [si]
    cmp     bl, '0'
    jb      .done
    cmp     bl, '9'
    ja      .done
    sub     bl, '0'
    mov     dx, 10
    mul     dx
    xor     bh, bh
    add     ax, bx
    inc     si
    inc     cx
    jmp     .loop
.done:
    test    cx, cx
    jz      .fail
    pop     si
    clc
    ret
.fail:
    pop     si
    stc
    ret

_parse_hex_word:
    push    si
    xor     ax, ax
    mov     cx, 0
.loop:
    mov     bl, [si]
    call    _hex_nibble_val
    jc      .done
    shl     ax, 4
    or      al, bl
    inc     si
    inc     cx
    jmp     .loop
.done:
    test    cx, cx
    jz      .fail
    pop     si
    clc
    ret
.fail:
    pop     si
    stc
    ret

_hex_nibble_val:
    cmp     bl, '0'
    jb      .bad
    cmp     bl, '9'
    ja      .alpha
    sub     bl, '0'
    clc
    ret
.alpha:
    or      bl, 0x20
    cmp     bl, 'a'
    jb      .bad
    cmp     bl, 'f'
    ja      .bad
    sub     bl, 0x57
    clc
    ret
.bad:
    stc
    ret

_vga_str_es:
    push    si
    push    di
.loop:
    lodsb
    test    al, al
    jz      .done
    mov     [es:di], ax
    add     di, 2
    jmp     .loop
.done:
    pop     di
    pop     si
    ret

LOG_LINE_WIDTH      equ 54
LOG_COLOR_WIDTH     equ 1
LOG_MAX_LINES       equ 256

engine_drive        db 0
nx_active           db 0
smep_active         db 0
cpuid_edx_feat      dd 0
cpuid_ecx_feat      dd 0
conv_mem_kb         dw 0
selected_payload    dw 0
payload_count       dw 0
log_line_count      dw 0
log_scroll          dw 0
history_head        dw 0
history_count       dw 0
history_cursor      dw 0
input_len           dw 0
partial_offset      dw 0
log_color_temp      db 0
nibble_tmp          db 0, 0

cpu_vendor_buf      times 13 db 0
cpu_brand           times 50 db 0
decimal_buf         times 10 db 0
input_buffer        times INPUT_BUFFER_SIZE db 0
payload_table       times MAX_PAYLOAD_COUNT * 32 db 0
payload_flags       times MAX_PAYLOAD_COUNT db 0
history_buffer      times HISTORY_DEPTH * HISTORY_ENTRY_SIZE db 0
log_buffer          times LOG_MAX_LINES * LOG_LINE_WIDTH db 0
log_colors          times LOG_MAX_LINES db 0

str_title_bar       db "  SX-SANDBOX  >>  SHELLCODE EXECUTION & ANALYSIS ENVIRONMENT  //  x86 BARE-METAL", 0
str_title_right     db "BUILD 1.2.0", 0
str_subtitle        db "Active Environment: 16-bit Real Mode  |  Arch: x86  |  BIOS: Legacy INT", 0
str_panel_payloads  db "PAYLOADS", 0
str_panel_log       db "EXECUTION LOG", 0
str_status_bar      db "  [F1] Help  [TAB] Next  [ENTER] Run  |  run  list  sel <n>  dump <addr>  info  sandbox  clear", 0
str_prompt          db "sx-sandbox> ", 0
str_separator       db "----------------------------------------------", 0
str_sandbox_init    db "[SANDBOX] Running environment checks...", 0
str_nx_enabled      db "  [NX/DEP]  ACTIVE   -- exec protection detected", 0
str_nx_disabled     db "  [NX/DEP]  INACTIVE -- memory regions executable", 0
str_smep_on         db "  [SMEP]    ACTIVE   -- supervisor mode exec. prevented", 0
str_smep_off        db "  [SMEP]    INACTIVE -- ring0 exec of user pages allowed", 0
str_cpuid_vendor    db "  [CPUID]   Vendor identification:", 0
str_prefix_vendor   db "    Vendor  : ", 0
str_prefix_memory   db "    RAM     : ", 0
str_a20_on          db "  [A20]     ENABLED  -- full address space accessible", 0
str_a20_off         db "  [A20]     DISABLED -- wraparound mode active", 0
str_exec_start      db "[EXEC] Dispatching payload...", 0
str_prefix_exec     db "  Target  : ", 0
str_sandbox_check   db "  Sandbox : active | NX bypass: analyzing...", 0
str_no_payload      db "[ERR] No payload selected. Use: sel <n>", 0
str_unknown_cmd     db "[ERR] Unknown command. Type 'help' for usage.", 0
str_list_header     db "[PAYLOADS] Available shellcode modules:", 0
str_list_prefix     db "  [ ] ", 0
str_list_sel_prefix db "  [*] ", 0
str_info_header     db "[INFO] SX-SANDBOX System Information", 0
str_info_1          db "  Engine  : 16-bit real mode shellcode loader", 0
str_info_2          db "  Stage2  : Loaded at 0x7E00 (this module)", 0
str_info_3          db "  Sandbox : Loaded at 0x9000", 0
str_info_4          db "  Shellcode Base: 0xA000", 0
str_help_header     db "[HELP] Command Reference:", 0
str_help_run        db "  run              Execute selected payload", 0
str_help_list       db "  list             List available payloads", 0
str_help_sel        db "  sel <n>          Select payload by index", 0
str_help_sandbox    db "  sandbox          Re-run protection checks", 0
str_help_dump       db "  dump <hex_addr>  Hexdump 32 bytes at address", 0
str_help_info       db "  info             Show system information", 0
str_help_clear      db "  clear            Clear execution log", 0
str_sel_ok          db "[OK] Payload selected.", 0
str_sel_bad         db "[ERR] Invalid index. Use a number.", 0
str_sel_oob         db "[ERR] Index out of range.", 0
str_dump_bad        db "[ERR] Invalid address. Use hex (e.g. dump 7c00)", 0
str_kb_suffix       db " KB (conventional)", 0
str_prefix_addr     db "  [0x", 0
str_prefix_port     db "  PORT 0x", 0
str_prefix_ss       db "  SS: 0x", 0
str_prefix_sp       db "  SP: 0x", 0
str_prefix_brand    db "  Brand  : ", 0
str_prefix_stepping db "  Step   : ", 0
str_colon_space     db ": ", 0
str_arrow           db " -> 0x", 0
str_space           db " ", 0
str_feat_sse        db "  [FEAT] SSE  supported", 0
str_feat_sse2       db "  [FEAT] SSE2 supported", 0
str_feat_avx        db "  [FEAT] AVX  supported", 0
str_no_brand        db "  Brand string not available (CPUID < 0x80000004)", 0
str_pl_msgbox_1     db "[PAYLOAD:MSGBOX] Constructing position-independent stub...", 0
str_pl_msgbox_2     db "  OpCode: MOV AX,0xC0 / MOV ES,AX / RETF", 0
str_pl_injected     db "  Shellcode written to 0xA000. Transferring control...", 0
str_pl_returned     db "  Returned cleanly. Stack integrity: OK", 0
str_pl_memwalk_1    db "[PAYLOAD:MEMWALK] Dumping BIOS Data Area (0x0400+):", 0
str_pl_port_1       db "[PAYLOAD:PORTPROBE] Sampling I/O ports (0x03F8 base):", 0
str_pl_stack_1      db "[PAYLOAD:STACKSMASH] Analyzing stack frame integrity...", 0
str_pl_stack_2      db "  Writing canary pattern 0xDEAD x4...", 0
str_pl_stack_ok     db "  All canaries intact. Stack integrity: PASS", 0
str_pl_stack_corrupt db "[ERR] Stack corruption detected!", 0
str_pl_nx_1         db "[PAYLOAD:NXPROBE] Testing execute permission on data segment...", 0
str_pl_nx_exec      db "  NX inactive. Writing RET stub to 0xA000 and executing...", 0
str_pl_nx_done      db "  Execution succeeded. NX enforcement: ABSENT", 0
str_pl_nx_blocked   db "  NX active. Execution attempt would fault. Skipping.", 0
str_pl_cpu_1        db "[PAYLOAD:CPUINFO] Enumerating CPU via CPUID leaves...", 0
str_payload_msgbox  db "MSGBOX  - Segment probe payload", 0
str_payload_memwalk db "MEMWALK - BDA memory walker", 0
str_payload_portprobe db "PORTPROBE - I/O port sampler", 0
str_payload_stacksmash db "STACKSMASH - Canary integrity test", 0
str_payload_nxprobe db "NXPROBE - NX/DEP execution test", 0
str_payload_cpuinfo db "CPUINFO - Full CPUID enumeration", 0

cmd_run     db "RUN", 0
cmd_list    db "LIST", 0
cmd_info    db "INFO", 0
cmd_clear   db "CLEAR", 0
cmd_help    db "HELP", 0
cmd_sel     db "SEL", 0
cmd_sandbox db "SANDBOX", 0
cmd_dump    db "DUMP", 0

times 6144 - ($ - $$) db 0
