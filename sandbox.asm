BITS 16
ORG 0x9000

POLICY_ALLOW_ALL        equ 0x00
POLICY_BLOCK_DANGER     equ 0x01
POLICY_AUDIT_ONLY       equ 0x02
POLICY_LOCKDOWN         equ 0x03

EXEC_FLAG_PIC           equ 0x01
EXEC_FLAG_DANGEROUS     equ 0x02
EXEC_FLAG_RING0         equ 0x04
EXEC_FLAG_IO_ACCESS     equ 0x08

REPORT_BASE             equ 0x8000
REPORT_MAX_ENTRIES      equ 32
REPORT_ENTRY_SIZE       equ 48

SHELLCODE_EXEC_BASE     equ 0xA000
SHELLCODE_EXEC_LIMIT    equ 0xAFFF

MAX_HOOK_COUNT          equ 16
IVT_BASE                equ 0x0000
IVT_ENTRY_SIZE          equ 4

VGA_TEXT_MEM            equ 0xB800
COLOR_POLICY_ALLOW      equ 0x0A
COLOR_POLICY_BLOCK      equ 0x0C
COLOR_POLICY_AUDIT      equ 0x0E
COLOR_POLICY_INFO       equ 0x0B

sandbox_entry:
    push    bp
    mov     bp, sp
    pusha
    push    ds
    push    es

    xor     ax, ax
    mov     ds, ax
    mov     es, ax

    mov     ax, [bp + 8]
    mov     [sb_payload_flags], al

    mov     ax, [bp + 6]
    mov     [sb_payload_index], ax

    call    _sb_pre_exec_analysis
    jc      .block

    call    _sb_snapshot_ivt
    call    _sb_snapshot_registers

    clc
    jmp     .done

.block:
    stc

.done:
    pop     es
    pop     ds
    popa
    pop     bp
    ret     4

sandbox_post_exec:
    pusha
    push    ds
    push    es
    xor     ax, ax
    mov     ds, ax
    mov     es, ax

    call    _sb_diff_ivt
    call    _sb_check_register_state
    call    _sb_record_exec_event
    call    _sb_update_policy_score

    pop     es
    pop     ds
    popa
    ret

sandbox_query_policy:
    push    bx
    mov     al, [active_policy]
    pop     bx
    ret

sandbox_set_policy:
    cmp     al, POLICY_LOCKDOWN
    ja      .invalid
    mov     [active_policy], al
    call    _sb_log_policy_change
    clc
    ret
.invalid:
    stc
    ret

sandbox_get_report:
    push    bx
    push    cx
    mov     bx, report_buffer
    mov     cx, [report_entry_count]
    pop     cx
    pop     bx
    ret

sandbox_reset:
    pusha
    call    _sb_clear_report
    call    _sb_reset_hooks
    mov     byte [active_policy], POLICY_BLOCK_DANGER
    mov     word [report_entry_count], 0
    mov     word [violation_count], 0
    mov     word [exec_count], 0
    mov     byte [policy_score], 100
    popa
    ret

_sb_pre_exec_analysis:
    pusha

    mov     al, [sb_payload_flags]
    test    al, EXEC_FLAG_DANGEROUS
    jz      .check_policy
    cmp     byte [active_policy], POLICY_BLOCK_DANGER
    jge     .blocked_dangerous
    jmp     .check_policy

.check_policy:
    cmp     byte [active_policy], POLICY_LOCKDOWN
    je      .blocked_lockdown

    cmp     byte [active_policy], POLICY_AUDIT_ONLY
    je      .audit_pass

    call    _sb_verify_payload_bounds
    jc      .blocked_bounds

    call    _sb_scan_payload_opcodes
    jc      .blocked_opcode

    popa
    clc
    ret

.blocked_dangerous:
    mov     si, str_sb_blocked_danger
    call    _sb_log_violation
    inc     word [violation_count]
    popa
    stc
    ret

.blocked_lockdown:
    mov     si, str_sb_lockdown
    call    _sb_log_violation
    inc     word [violation_count]
    popa
    stc
    ret

.blocked_bounds:
    mov     si, str_sb_out_of_bounds
    call    _sb_log_violation
    inc     word [violation_count]
    popa
    stc
    ret

.blocked_opcode:
    mov     si, str_sb_bad_opcode
    call    _sb_log_violation
    inc     word [violation_count]
    popa
    stc
    ret

.audit_pass:
    mov     si, str_sb_audit_pass
    call    _sb_log_info
    popa
    clc
    ret

_sb_verify_payload_bounds:
    push    ax
    push    bx
    mov     ax, SHELLCODE_EXEC_BASE
    cmp     ax, SHELLCODE_EXEC_BASE
    jb      .oob
    cmp     ax, SHELLCODE_EXEC_LIMIT
    ja      .oob
    pop     bx
    pop     ax
    clc
    ret
.oob:
    pop     bx
    pop     ax
    stc
    ret

_sb_scan_payload_opcodes:
    push    es
    push    si
    push    cx
    push    bx

    xor     ax, ax
    mov     es, ax
    mov     si, SHELLCODE_EXEC_BASE
    mov     cx, 64

.scan_loop:
    mov     al, [es:si]

    cmp     al, 0xEE
    je      .flag_io
    cmp     al, 0xEF
    je      .flag_io
    cmp     al, 0xEC
    je      .flag_io
    cmp     al, 0xED
    je      .flag_io

    cmp     al, 0xFA
    je      .flag_cli
    cmp     al, 0x0F
    je      .check_0f

    cmp     al, 0xCD
    je      .check_int

    inc     si
    loop    .scan_loop
    pop     bx
    pop     cx
    pop     si
    pop     es
    clc
    ret

.check_0f:
    inc     si
    dec     cx
    jz      .scan_done
    mov     al, [es:si]
    cmp     al, 0x01
    je      .flag_privileged
    cmp     al, 0x09
    je      .flag_wbinvd
    cmp     al, 0x30
    je      .flag_privileged
    cmp     al, 0x32
    je      .flag_privileged
    inc     si
    loop    .scan_loop
    jmp     .scan_done

.check_int:
    inc     si
    dec     cx
    jz      .scan_done
    mov     al, [es:si]
    cmp     al, 0x13
    je      .flag_int13
    cmp     al, 0x1A
    je      .flag_rtc
    cmp     al, 0x15
    je      .flag_extended
    inc     si
    loop    .scan_loop
    jmp     .scan_done

.flag_io:
    mov     byte [scan_flags], EXEC_FLAG_IO_ACCESS
    mov     si, str_sb_scan_io
    call    _sb_log_info
    jmp     .scan_done_ok

.flag_cli:
    mov     si, str_sb_scan_cli
    call    _sb_log_info
    jmp     .scan_done_ok

.flag_privileged:
    mov     si, str_sb_scan_priv
    call    _sb_log_violation
    pop     bx
    pop     cx
    pop     si
    pop     es
    stc
    ret

.flag_wbinvd:
    mov     si, str_sb_scan_wbinvd
    call    _sb_log_violation
    pop     bx
    pop     cx
    pop     si
    pop     es
    stc
    ret

.flag_int13:
    mov     si, str_sb_scan_int13
    call    _sb_log_info
    jmp     .scan_done_ok

.flag_rtc:
    mov     si, str_sb_scan_rtc
    call    _sb_log_info
    jmp     .scan_done_ok

.flag_extended:
    mov     si, str_sb_scan_e820
    call    _sb_log_info
    jmp     .scan_done_ok

.scan_done_ok:
.scan_done:
    pop     bx
    pop     cx
    pop     si
    pop     es
    clc
    ret

_sb_snapshot_ivt:
    pusha
    push    es
    push    ds

    xor     ax, ax
    mov     ds, ax
    mov     es, ax

    mov     si, IVT_BASE
    mov     di, ivt_snapshot
    mov     cx, 256 * 2
    rep     movsw

    pop     ds
    pop     es
    popa
    ret

_sb_diff_ivt:
    pusha
    push    es
    push    ds

    xor     ax, ax
    mov     ds, ax
    mov     es, ax

    mov     si, IVT_BASE
    mov     di, ivt_snapshot
    mov     cx, 256
    xor     bx, bx

.check_vector:
    mov     ax, [si]
    cmp     ax, [di]
    jne     .vector_modified
    mov     ax, [si + 2]
    cmp     ax, [di + 2]
    jne     .vector_modified
    add     si, 4
    add     di, 4
    inc     bx
    loop    .check_vector
    jmp     .done

.vector_modified:
    push    cx
    push    bx
    mov     [sb_modified_vector], bx
    mov     ax, [si]
    mov     [sb_new_handler_off], ax
    mov     ax, [si + 2]
    mov     [sb_new_handler_seg], ax
    mov     ax, [di]
    mov     [sb_old_handler_off], ax
    mov     ax, [di + 2]
    mov     [sb_old_handler_seg], ax
    pop     bx
    pop     cx

    mov     si, str_sb_ivt_mod
    call    _sb_log_violation
    inc     word [violation_count]
    inc     word [ivt_mods_detected]

    add     si, 4
    add     di, 4
    inc     bx
    loop    .check_vector

.done:
    pop     ds
    pop     es
    popa
    ret

_sb_snapshot_registers:
    mov     [reg_snap_ax], ax
    mov     [reg_snap_bx], bx
    mov     [reg_snap_cx], cx
    mov     [reg_snap_dx], dx
    mov     [reg_snap_si], si
    mov     [reg_snap_di], di
    mov     [reg_snap_bp], bp
    mov     [reg_snap_sp], sp
    mov     [reg_snap_ss], ss
    mov     [reg_snap_ds], ds
    mov     [reg_snap_es], es
    pushf
    pop     ax
    mov     [reg_snap_flags], ax
    ret

_sb_check_register_state:
    pusha
    mov     ax, ss
    cmp     ax, [reg_snap_ss]
    jne     .ss_modified

    mov     ax, ds
    cmp     ax, [reg_snap_ds]
    jne     .ds_modified

    jmp     .done

.ss_modified:
    mov     si, str_sb_ss_changed
    call    _sb_log_violation
    inc     word [violation_count]
    jmp     .done

.ds_modified:
    mov     si, str_sb_ds_changed
    call    _sb_log_violation
    inc     word [violation_count]

.done:
    popa
    ret

_sb_record_exec_event:
    pusha

    mov     ax, [report_entry_count]
    cmp     ax, REPORT_MAX_ENTRIES
    jge     .full

    mov     bx, REPORT_ENTRY_SIZE
    mul     bx
    mov     di, report_buffer
    add     di, ax

    mov     ax, [exec_count]
    stosw

    mov     al, [sb_payload_index]
    stosb

    mov     al, [sb_payload_flags]
    stosb

    mov     al, [active_policy]
    stosb

    mov     al, [violation_count]
    stosb

    inc     word [exec_count]
    inc     word [report_entry_count]

.full:
    popa
    ret

_sb_update_policy_score:
    pusha
    mov     al, [policy_score]
    mov     bx, [violation_count]
    cmp     bx, 0
    je      .no_violations

    cmp     bx, 5
    jge     .heavy_penalty

    sub     al, 5
    jmp     .update

.heavy_penalty:
    sub     al, 15

.update:
    jnc     .store
    xor     al, al
.store:
    mov     [policy_score], al

.no_violations:
    popa
    ret

_sb_log_policy_change:
    pusha
    mov     si, str_sb_policy_change
    call    _sb_log_info
    popa
    ret

_sb_log_violation:
    pusha
    push    ds
    push    es

    xor     ax, ax
    mov     ds, ax
    mov     es, ax

    mov     ax, [sb_log_ptr]
    cmp     ax, SB_LOG_MAX * SB_LOG_ENTRY
    jge     .full

    mov     di, sb_log_buffer
    add     di, ax

    mov     byte [di], 0x01
    inc     di

    mov     cx, SB_LOG_ENTRY - 2
.copy:
    lodsb
    test    al, al
    jz      .pad
    stosb
    loop    .copy
    jmp     .done
.pad:
    xor     al, al
    rep     stosb
.done:
    mov     byte [di], 0
    add     word [sb_log_ptr], SB_LOG_ENTRY
    inc     word [sb_log_count]

.full:
    pop     es
    pop     ds
    popa
    ret

_sb_log_info:
    pusha
    push    ds
    push    es

    xor     ax, ax
    mov     ds, ax
    mov     es, ax

    mov     ax, [sb_log_ptr]
    cmp     ax, SB_LOG_MAX * SB_LOG_ENTRY
    jge     .full

    mov     di, sb_log_buffer
    add     di, ax

    mov     byte [di], 0x00
    inc     di

    mov     cx, SB_LOG_ENTRY - 2
.copy:
    lodsb
    test    al, al
    jz      .pad
    stosb
    loop    .copy
    jmp     .done
.pad:
    xor     al, al
    rep     stosb
.done:
    mov     byte [di], 0
    add     word [sb_log_ptr], SB_LOG_ENTRY
    inc     word [sb_log_count]

.full:
    pop     es
    pop     ds
    popa
    ret

_sb_clear_report:
    pusha
    mov     di, report_buffer
    mov     cx, REPORT_MAX_ENTRIES * REPORT_ENTRY_SIZE
    xor     al, al
    rep     stosb
    mov     word [report_entry_count], 0
    popa
    ret

_sb_reset_hooks:
    pusha
    mov     di, sb_log_buffer
    mov     cx, SB_LOG_MAX * SB_LOG_ENTRY
    xor     al, al
    rep     stosb
    mov     word [sb_log_ptr], 0
    mov     word [sb_log_count], 0
    popa
    ret

SB_LOG_MAX              equ 64
SB_LOG_ENTRY            equ 48

active_policy           db POLICY_BLOCK_DANGER
policy_score            db 100
violation_count         dw 0
exec_count              dw 0
ivt_mods_detected       dw 0
report_entry_count      dw 0
sb_log_ptr              dw 0
sb_log_count            dw 0

sb_payload_flags        db 0
sb_payload_index        dw 0
scan_flags              db 0

sb_modified_vector      dw 0
sb_new_handler_off      dw 0
sb_new_handler_seg      dw 0
sb_old_handler_off      dw 0
sb_old_handler_seg      dw 0

reg_snap_ax             dw 0
reg_snap_bx             dw 0
reg_snap_cx             dw 0
reg_snap_dx             dw 0
reg_snap_si             dw 0
reg_snap_di             dw 0
reg_snap_bp             dw 0
reg_snap_sp             dw 0
reg_snap_ss             dw 0
reg_snap_ds             dw 0
reg_snap_es             dw 0
reg_snap_flags          dw 0

ivt_snapshot            times 256 * 4 db 0
report_buffer           times REPORT_MAX_ENTRIES * REPORT_ENTRY_SIZE db 0
sb_log_buffer           times SB_LOG_MAX * SB_LOG_ENTRY db 0

str_sb_blocked_danger   db "[SANDBOX:BLOCK] Payload flagged DANGEROUS -- policy BLOCK_DANGER active", 0
str_sb_lockdown         db "[SANDBOX:BLOCK] Execution denied -- LOCKDOWN policy active", 0
str_sb_out_of_bounds    db "[SANDBOX:BLOCK] Payload origin outside permitted exec region", 0
str_sb_bad_opcode       db "[SANDBOX:BLOCK] Privileged/unsafe opcode detected in payload", 0
str_sb_audit_pass       db "[SANDBOX:AUDIT] Execution permitted -- audit-only policy", 0
str_sb_ivt_mod          db "[SANDBOX:ALERT] IVT vector modified after execution", 0
str_sb_ss_changed       db "[SANDBOX:ALERT] Stack segment modified by payload", 0
str_sb_ds_changed       db "[SANDBOX:ALERT] Data segment modified by payload", 0
str_sb_scan_io          db "[SANDBOX:SCAN]  I/O port access opcode detected (IN/OUT)", 0
str_sb_scan_cli         db "[SANDBOX:SCAN]  CLI instruction detected (interrupt disable)", 0
str_sb_scan_priv        db "[SANDBOX:BLOCK] Privileged MSR/system opcode in payload", 0
str_sb_scan_wbinvd      db "[SANDBOX:BLOCK] WBINVD cache flush instruction detected", 0
str_sb_scan_int13       db "[SANDBOX:SCAN]  INT 13h disk access in payload", 0
str_sb_scan_rtc         db "[SANDBOX:SCAN]  INT 1Ah RTC access in payload", 0
str_sb_scan_e820        db "[SANDBOX:SCAN]  INT 15h extended memory query detected", 0
str_sb_policy_change    db "[SANDBOX:POLICY] Active enforcement policy updated", 0

times 4096 - ($ - $$) db 0
