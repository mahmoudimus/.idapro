.text:000000018020CE1E 7D 4A                                               jge     short near ptr loc_18020CE69+1
.text:000000018020CE20 86 F6                                               xchg    dh, dh
.text:000000018020CE22 7C 46                                               jl      short near ptr loc_18020CE69+1
.text:000000018020CE24 66 90                                               xchg    ax, ax
.text:000000018020CE26 66 90                                               xchg    ax, ax
.text:000000018020CE28 F6 D9                                               neg     cl
.text:000000018020CE2A 0F 8A 97 D0 01 00                                   jp      loc_180229EC7
.text:000000018020CE30 81 C6 2D 01 E4 75                                   add     esi, 75E4012Dh
.text:000000018020CE36 80 E8 85                                            sub     al, 85h
.text:000000018020CE39 83 C0 FD                                            add     eax, 0FFFFFFFDh
.text:000000018020CE3C 81 EF BA 16 F9 10                                   sub     edi, 10F916BAh
.text:000000018020CE42 0F 89 6C 56 01 00                                   jns     loc_1802224B4
.text:000000018020CE48 0F 87 13 04 01 00                                   ja      loc_18021D261
.text:000000018020CE4E 81 EA 0A 3C 8C E6                                   sub     edx, 0E68C3C0Ah
.text:000000018020CE54 81 E9 F4 C4 C0 CC                                   sub     ecx, 0CCC0C4F4h
.text:000000018020CE5A 0F 8F 75 98 01 00                                   jg      near ptr off_1802266D0+5 ; "mk-mk"
.text:000000018020CE60 6A 3D                                               push    3Dh ; '='
.text:000000018020CE62 C0 B8 DB C2 95 D1 9E                                sar     byte ptr [rax-2E6A3D25h], 9Eh
.text:000000018020CE69
.text:000000018020CE69                                     loc_18020CE69:                          ; CODE XREF: sub_180207ED0+4F4E↑j
.text:000000018020CE69                                                                             ; sub_180207ED0+4F52↑j
.text:000000018020CE69 3D 48 89 7C 24                                      cmp     eax, 247C8948h
.text:000000018020CE6E 28 4C 89 74                                         sub     [rcx+rcx*4+74h], cl
.text:000000018020CE72 24 20                                               and     al, 20h
.text:000000018020CE74 B9 25 00 00 00                                      mov     ecx, 25h ; '%'
.text:000000018020CE79 BA 4A 00 00 00                                      mov     edx, 4Ah ; 'J'
.text:000000018020CE7E 41 B9 10 00 00 00                                   mov     r9d, 10h
.text:000000018020CE84 E9 E7 00 00 00                                      jmp     loc_18020CF70
.text:000000018020CE89                                     ; ---------------------------------------------------------------------------
.text:000000018020CE89
.text:000000018020CE89                                     loc_18020CE89:                          ; CODE XREF: sub_180207ED0+2E02↑j
.text:000000018020CE89                                                                             ; DATA XREF: .rdata:jpt_18020ACD2↓o
.text:000000018020CE89 48 8D 47 0B                                         lea     rax, [rdi+0Bh]  ; jumptable 000000018020ACD2 case 140
.text:000000018020CE8D 48 89 44 24 20                                      mov     [rsp+4A8h+var_488], rax
.text:000000018020CE92 BA 2B 00 00 00                                      mov     edx, 2Bh ; '+'
.text:000000018020CE97 41 B8 12 00 00 00                                   mov     r8d, 12h        ; CODE XREF: sub_1801FB880+34↑p
.text:000000018020CE9D 41 B9 45 00 00 00                                   mov     r9d, 45h ; 'E'
.text:000000018020CEA3 48 89 F1                                            mov     rcx, rsi        ; CODE XREF: sub_1801F3B90+1762↑p
.text:000000018020CEA6 E8 45 CD F2 FF                                      call    sub_180139BF0