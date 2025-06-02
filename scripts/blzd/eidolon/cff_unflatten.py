VIRTUALIZED_API_RESOLVER_PSEUDOCODE = """\
void VirtualizedApiResolver(uint8_t *bytecodeTable, uint64_t seed) 
{
    // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]
    n2 = 0;
    while ( 1 )
    {
        switch ( n2 )
        {
            case 0:
                n2 = 1;
                break;
            case 1:
                v19 = 0xAB;
                v20 = 0;
                n2 = 2;
                break;
            case 2:
                n2 = 3;
                break;
            case 3:
                n0x77 = 4 * (v20 ^ 1);
                sub_1801C72D0(0x5E, 0x36, 0x39, &n0x77);
                n0x77_1 = n0x77;
                n2 = 4;
                break;
            case 4:
                BYTE2(n0x77_2) = n0x77_1 + 0x3A;
                v22 = (unsigned __int8)(n0x77_1 + 0x3A) >> 4;
                n2 = 5;
                break;
            case 5:
                v23 = 0x10 * p_InLoadOrderModuleList_8[v22];
                n2 = 6;
                break;
            case 6:
                v24 = p_InLoadOrderModuleList_8[BYTE2(n0x77_2) & 0xF] | v23;
                n2 = 7;
                break;
            case 7:
                v68 = 0xF52F742A;
                n2 = 8;
                break;
            case 8:
                v70 = __ROL4__(v68 + 0x22F1E3F2, 0x16);
                n2 = 9;
                break;
            case 9:
                v71 = __ROL4__((v70 ^ 0x1D51E806) - 0x1A57E050, 1);
                n2 = 0xA;
                break;
            case 0xA:
                v72 = qword_180281ADF;
                v169 = (_QWORD *)(qword_180284078 + 8);
                v170 = (_DWORD *)(qword_180284078 + 0x10);
                v73 = dword_180281D52;
                v64 = v71;
                n2 = 0xB;
                break;
            case 0xB:
                v45 = v64;
                v9 = sub_180094930(0x4E, 0x2B, 0x5C);
                v17 = v24;
                if ( v45 >= v9 )
                    n2 = 0xC;
                else
                    n2 = 0xC1;
                break;
            case 0xC:
                v25 = v17;
                v26 = BYTE4(qword_180281C90);
                n2 = 0xD;
                break;
            case 0xD:
                v27 = v26 ^ v25 ^ 0x79;
                v177 = &byte_1802272E0[v27 >> 4];
                n2 = 0xE;
                break;
            case 0xE:
                v28 = 0x10 * *v177;
                v178 = v27 & 0xF ^ 0xBLL;
                n2 = 0xF;
                break;
            case 0xF:
                BYTE1(n0x77_2) = (byte_1802272E0[v178] | v28) - 0x3A;
                sub_180143830((char *)&n0x77_2 + 1, 0x15, 0x11, 0x56);
                n2 = 0x10;
                break;
            case 0x10:
                if ( BYTE1(n0x77_2) )
                    n2 = 0x11;
                else
                    n2 = 0x12;
                break;
            case 0x11:
                v3 = sub_180207670(0x59, 0x1B, 7, 0xEA60);
                sub_1800E0770(0x53, 0x10, v3, 0x1E);
                n2 = 1;
                break;
            case 0x12:
                n0x6AC3DC33 = 0x6AC3DC33;
                v74 = __ROL4__(0x6AC3DC33, 2);
                n2 = 0x13;
                break;
            case 0x13:
                v75 = __ROL4__((v74 ^ 0x2F642FA8) + 0x7B95219B, 0x19);
                n2 = 0x14;
                break;
            case 0x14:
                n2 = 0x15;
                break;
            case 0x15:
                v76 = __ROL4__(v75, 0xC) ^ 0x1445306A;
                n2 = 0x16;
                break;
            case 0x16:
                v60 = __ROL4__(v76 - 0x34B92CEE, 0xF);
                sub_180034460(0x2B, 0xF, 0x25, &v60, n0xA);
                n2 = 0x17;
                break;
            case 0x17:
                v77 = (v60 ^ 0xA70B480C) - 0x71DCDC6A;
                v46 = v77;
                n2 = 0x18;
                break;
            case 0x18:
                v179 = v46 >> 8;
                v78 = p_InLoadOrderModuleList_10[(unsigned __int16)v46 >> 0xC] << 0xC;
                n2 = 0x19;
                break;
            case 0x19:
                v180 = v46 >> 0x18;
                v79 = p_InLoadOrderModuleList_10[v46 >> 0x1C] << 0x1C;
                n2 = 0x1A;
                break;
            case 0x1A:
                v80 = v78 | v79;
                v29 = v77;
                v181 = &p_InLoadOrderModuleList_10[v77 & 0xF];
                n2 = 0x1B;
                break;
            case 0x1B:
                v81 = v80 | *v181;
                v182 = v46 >> 0x10;
                v183 = v46 >> 0x14;
                n2 = 0x1C;
                break;
            case 0x1C:
                v82 = v81 | (p_InLoadOrderModuleList_10[v183 & 0xF] << 0x14);
                n2 = 0x1D;
                break;
            case 0x1D:
                v83 = v82 | (p_InLoadOrderModuleList_10[v180 & 0xF] << 0x18);
                n2 = 0x1E;
                break;
            case 0x1E:
                v184 = &p_InLoadOrderModuleList_10[v179 & 0xF];
                n2 = 0x1F;
                break;
            case 0x1F:
                v84 = v83 | (*v184 << 8);
                n2 = 0x20;
                break;
            case 0x20:
                v61 = v84 | (0x10 * p_InLoadOrderModuleList_10[v29 >> 4]);
                n2 = 0x21;
                break;
            case 0x21:
                v85 = v61 | (p_InLoadOrderModuleList_10[v182 & 0xF] << 0x10);
                n2 = 0x22;
                break;
            case 0x22:
                n2 = 0x23;
                break;
            case 0x23:
                v65 = v85;
                n2 = 0x24;
                break;
            case 0x24:
                v185 = v65 >> 8;
                v86 = p_InLoadOrderModuleList_1[(unsigned __int16)v65 >> 0xC] << 0xC;
                n2 = 0x25;
                break;
            case 0x25:
                v186 = v65 >> 0x18;
                v87 = v86 | (p_InLoadOrderModuleList_1[v65 >> 0x1C] << 0x1C);
                n2 = 0x26;
                break;
            case 0x26:
                v30 = v61;
                v187 = v61 & 0xF;
                n2 = 0x27;
                break;
            case 0x27:
                v88 = v87 | p_InLoadOrderModuleList_1[v187];
                v188 = v65 >> 0x10;
                v189 = v65 >> 0x14;
                n2 = 0x28;
                break;
            case 0x28:
                v89 = v88 | (p_InLoadOrderModuleList_1[v189 & 0xF] << 0x14);
                n2 = 0x29;
                break;
            case 0x29:
                v90 = v89 | (p_InLoadOrderModuleList_1[v186 & 0xF] << 0x18);
                n2 = 0x2A;
                break;
            case 0x2A:
                v91 = p_InLoadOrderModuleList_1[v185 & 0xF];
                n2 = 0x2B;
                break;
            case 0x2B:
                v92 = v90 | (v91 << 8);
                v190 = &p_InLoadOrderModuleList_1[v30 >> 4];
                n2 = 0x2C;
                break;
            case 0x2C:
                v93 = v92 | (0x10 * *v190);
                v191 = v188 & 0xF;
                n2 = 0x2D;
                break;
            case 0x2D:
                v50 = ((v93 | (p_InLoadOrderModuleList_1[v191] << 0x10)) + 0x71DCDC6A) ^ 0xA70B480C;
                n2 = 0x2E;
                break;
            case 0x2E:
                sub_18011C8C0(0x5A, 0xA, &v50);
                v94 = v50;
                v95 = qword_180281BFA;
                n2 = 0x2F;
                break;
            case 0x2F:
                v192 = n0x72 ^ 0x72;
                n2 = 0x30;
                break;
            case 0x30:
                v157 = v192;
                sub_1800A91F0(0x4B, &v157);
                v18 = __ROL8__(v157, 0x35) - 0x565D6B6FAFF7EB35LL;
                n2 = 0x31;
                break;
            case 0x31:
                v193 = HIWORD(v18);
                v31 = p_InLoadOrderModuleList_5[(v18 >> 0x34) & 0xF];
                n2 = 0x32;
                break;
            case 0x32:
                v194 = (unsigned __int64)v31 << 0x34;
                v195 = v18 >> 0x18;
                v196 = (unsigned int)v18 >> 0x1C;
                n2 = 0x33;
                break;
            case 0x33:
                v197 = v194 | ((unsigned __int64)p_InLoadOrderModuleList_5[v196] << 0x1C);
                n2 = 0x34;
                break;
            case 0x34:
                v198 = p_InLoadOrderModuleList_5[BYTE2(v18) & 0xF] << 0x10;
                n2 = 0x35;
                break;
            case 0x35:
                v199 = v198 | v197;
                v32 = p_InLoadOrderModuleList_5[((unsigned int)v18 >> 0x14) & 0xF];
                n2 = 0x36;
                break;
            case 0x36:
                v200 = v199 | (v32 << 0x14);
                v201 = v18 & 0xF;
                n2 = 0x37;
                break;
            case 0x37:
                v202 = v200 | p_InLoadOrderModuleList_5[v201];
                v203 = HIBYTE(v18);
                n2 = 0x38;
                break;
            case 0x38:
                v204 = v202 | ((unsigned __int64)p_InLoadOrderModuleList_5[v203 & 0xF] << 0x38);
                n2 = 0x39;
                break;
            case 0x39:
                v205 = v18 >> 8;
                v33 = p_InLoadOrderModuleList_5[(unsigned __int16)v18 >> 0xC];
                n2 = 0x3A;
                break;
            case 0x3A:
                v206 = v204 | (v33 << 0xC);
                v207 = HIDWORD(v18);
                v208 = (v18 >> 0x24) & 0xF;
                n2 = 0x3B;
                break;
            case 0x3B:
                v209 = v206 | ((unsigned __int64)p_InLoadOrderModuleList_5[v208] << 0x24);
                n2 = 0x3C;
                break;
            case 0x3C:
                v210 = v209 | (p_InLoadOrderModuleList_5[v195 & 0xF] << 0x18);
                n2 = 0x3D;
                break;
            case 0x3D:
                v211 = v210
                     | (0x10 * (unsigned int)p_InLoadOrderModuleList_5[(unsigned __int8)v18 >> 4]);
                n2 = 0x3E;
                break;
            case 0x3E:
                v212 = v211 | ((unsigned __int64)p_InLoadOrderModuleList_5[v193 & 0xF] << 0x30);
                n2 = 0x3F;
                break;
            case 0x3F:
                v213 = v18 >> 0x28;
                v34 = p_InLoadOrderModuleList_5[(v18 >> 0x2C) & 0xF];
                n2 = 0x40;
                break;
            case 0x40:
                v214 = v212 | ((unsigned __int64)v34 << 0x2C);
                v215 = &p_InLoadOrderModuleList_5[v205 & 0xF];
                n2 = 0x41;
                break;
            case 0x41:
                v216 = v214 | (*v215 << 8);
                v217 = v213 & 0xF;
                n2 = 0x42;
                break;
            case 0x42:
                v218 = v216 | ((unsigned __int64)p_InLoadOrderModuleList_5[v217] << 0x28);
                n2 = 0x43;
                break;
            case 0x43:
                v219 = v218 | ((unsigned __int64)p_InLoadOrderModuleList_5[v207 & 0xF] << 0x20);
                n2 = 0x44;
                break;
            case 0x44:
                v220 = __ROL8__(
                           v219 | ((unsigned __int64)p_InLoadOrderModuleList_5[v18 >> 0x3C] << 0x3C),
                           0x3D);
                n2 = 0x45;
                break;
            case 0x45:
                v221 = v220 ^ qword_180281B27 ^ 0x8F37476A75A49085uLL;
                n2 = 0x46;
                break;
            case 0x46:
                v222 = v221;
                n2 = 0x47;
                break;
            case 0x47:
                n0x4CC74D88 = 0x4CC74D88;
                sub_18013CC60(0x33, 0x3A, 0x51, &n0x4CC74D88);
                v96 = n0x4CC74D88 - 0x425E0292;
                n2 = 0x48;
                break;
            case 0x48:
                v2 = sub_1800E4350(0x20, v222 + 0x5C, 0xE, 0x51);
                if ( v2 == v96 )
                    n2 = 0x49;
                else
                    n2 = 0x11;
                break;
            case 0x49:
                v97 = __ROL4__(v95 ^ (__ROL4__(v94, 0x11) + 0x34B92CEE) ^ 0x64, 0x14);
                n2 = 0x4A;
                break;
            case 0x4A:
                n0x72 = n0x72;
                n2 = 0x4B;
                break;
            case 0x4B:
                v158 = n0x72 ^ 0x72;
                sub_1800A91F0(0xF, &v158);
                n2 = 0x4C;
                break;
            case 0x4C:
                v43 = __ROL8__(v158, 0x35) - 0x565D6B6FAFF7EB35LL;
                n2 = 0x4D;
                break;
            case 0x4D:
                v224 = HIWORD(v43);
                v225 = p_InLoadOrderModuleList_5[(v43 >> 0x34) & 0xF];
                n2 = 0x4E;
                break;
            case 0x4E:
                v226 = v225 << 0x34;
                v227 = v43 >> 0x18;
                v228 = &p_InLoadOrderModuleList_5[(unsigned int)v43 >> 0x1C];
                n2 = 0x4F;
                break;
            case 0x4F:
                v229 = v226 | ((unsigned __int64)*v228 << 0x1C);
                v230 = v43 >> 0x10;
                n2 = 0x50;
                break;
            case 0x50:
                v231 = v229 | (p_InLoadOrderModuleList_5[v230 & 0xF] << 0x10);
                n2 = 0x51;
                break;
            case 0x51:
                v232 = v231 | (p_InLoadOrderModuleList_5[((unsigned int)v43 >> 0x14) & 0xF] << 0x14);
                n2 = 0x52;
                break;
            case 0x52:
                v233 = v232 | p_InLoadOrderModuleList_5[v43 & 0xF];
                n2 = 0x53;
                break;
            case 0x53:
                v234 = (unsigned __int64)p_InLoadOrderModuleList_5[HIBYTE(v43) & 0xF] << 0x38;
                n2 = 0x54;
                break;
            case 0x54:
                v235 = v234 | v233;
                v236 = v43 >> 8;
                v237 = &p_InLoadOrderModuleList_5[(unsigned __int16)v43 >> 0xC];
                n2 = 0x55;
                break;
            case 0x55:
                v238 = v235 | (*v237 << 0xC);
                n2 = 0x56;
                break;
            case 0x56:
                v239 = HIDWORD(v43);
                v240 = v238
                     | ((unsigned __int64)p_InLoadOrderModuleList_5[(v43 >> 0x24) & 0xF] << 0x24);
                n2 = 0x57;
                break;
            case 0x57:
                v241 = p_InLoadOrderModuleList_5[v227 & 0xF] << 0x18;
                n2 = 0x58;
                break;
            case 0x58:
                v242 = v241 | v240;
                v243 = p_InLoadOrderModuleList_5[(unsigned __int8)v43 >> 4];
                n2 = 0x59;
                break;
            case 0x59:
                v244 = v242 | (0x10 * v243);
                v245 = &p_InLoadOrderModuleList_5[v224 & 0xF];
                n2 = 0x5A;
                break;
            case 0x5A:
                v246 = v244 | ((unsigned __int64)*v245 << 0x30);
                v247 = v43 >> 0x28;
                n2 = 0x5B;
                break;
            case 0x5B:
                v248 = (unsigned __int64)p_InLoadOrderModuleList_5[(v43 >> 0x2C) & 0xF] << 0x2C;
                n2 = 0x5C;
                break;
            case 0x5C:
                v249 = v248 | v246;
                v250 = p_InLoadOrderModuleList_5[v236 & 0xF];
                n2 = 0x5D;
                break;
            case 0x5D:
                v251 = v249 | (v250 << 8);
                v252 = v247 & 0xF;
                n2 = 0x5E;
                break;
            case 0x5E:
                v253 = v251 | ((unsigned __int64)p_InLoadOrderModuleList_5[v252] << 0x28);
                n2 = 0x5F;
                break;
            case 0x5F:
                v254 = v253 | ((unsigned __int64)p_InLoadOrderModuleList_5[v239 & 0xF] << 0x20);
                n2 = 0x60;
                break;
            case 0x60:
                v255 = v254 | ((unsigned __int64)p_InLoadOrderModuleList_5[v43 >> 0x3C] << 0x3C);
                n2 = 0x61;
                break;
            case 0x61:
                v256 = qword_180281B27 ^ __ROL8__(v255, 0x3D) ^ 0x8F37476A75A49085uLL;
                n2 = 0x62;
                break;
            case 0x62:
                v176 = 0xFCC8A7499F179835uLL;
                v257 = 0xC01DB0ABC995A1BBuLL;
                n2 = 0x63;
                break;
            case 0x63:
                v258 = __ROL8__(v257 ^ 0xC01DB0B43615A1BBuLL, 0x3A);
                n2 = 0x64;
                break;
            case 0x64:
                n2 = 0x65;
                break;
            case 0x65:
                v259 = __ROL8__(__ROL8__(v258, 0x1F) ^ 0xE6603223AEA4D577uLL, 0x34);
                n2 = 0x66;
                break;
            case 0x66:
                v160 = (v259 ^ 0x7DC53AF5F68B1802LL) - 0x238D1C151101C288LL;
                sub_18011CB90(&v160, 0x51, 5, 0x3C);
                v171 = v160;
                n2 = 0x67;
                break;
            case 0x67:
                v161 = v171;
                n2 = 0x68;
                break;
            case 0x68:
                sub_1801BCFF0(0x31, &v161, 0xB, 0x23);
                v260 = (v161 + 0x238D1C151101C288LL) ^ 0x7DC53AF5F68B1802LL;
                n2 = 0x69;
                break;
            case 0x69:
                v172 = qword_180281BE0;
                v261 = __ROL8__(qword_180281BE0 ^ __ROL8__(v260, 0xC), 0x21);
                n2 = 0x6A;
                break;
            case 0x6A:
                v98 = *(_DWORD *)(v261 + 4);
                n2 = 0x6B;
                break;
            case 0x6B:
                v54 = v98;
                sub_1800769A0(0xB, &v54, 0xB, 0x37);
                v99 = v54;
                n2 = 0x6C;
                break;
            case 0x6C:
                v100 = __ROL4__(__ROL4__(v99, 0x13) ^ 0xFCAB611B, 9) + 0x4CC071E0;
                n2 = 0x6D;
                break;
            case 0x6D:
                n2 = 0x6E;
                break;
            case 0x6E:
                v162 = v171;
                sub_1801BCFF0(0x33, &v162, 7, 0x50);
                v262 = (v162 + 0x238D1C151101C288LL) ^ 0x7DC53AF5F68B1802LL;
                n2 = 0x6F;
                break;
            case 0x6F:
                v263 = __ROL8__(v172 ^ __ROL8__(v262, 0xC), 0x21);
                n2 = 0x70;
                break;
            case 0x70:
                v264 = *(_QWORD *)(v263 + 0x320);
                n2 = 0x71;
                break;
            case 0x71:
                v265 = __ROL8__(v264 - 0x39B39BF2411BD27CLL, 0x22) ^ 0xA4D8366B785927C3uLL;
                n2 = 0x72;
                break;
            case 0x72:
                v163 = v265;
                sub_180137D30(0x5F, 0x1A, 2, &v163);
                v266 = (v163 ^ 0xCA) - 0x4581C12A87917C75LL;
                n2 = 0x73;
                break;
            case 0x73:
                v267 = __ROL8__(v266 ^ 0x3DB71325EC41CAD9LL, 0x21);
                n2 = 0x74;
                break;
            case 0x74:
                v268 = __ROL8__(v267, 0x1F);
                n2 = 0x75;
                break;
            case 0x75:
                v164 = ((v268 ^ qword_180281CB4) + 0x4581C12A87917C75LL) ^ 0xCA;
                n2 = 0x76;
                break;
            case 0x76:
                sub_18008CE30(0x2B, 0xF, &v164, 0x63, n0xA);
                v270 = __ROL8__(v165 ^ 0xA4D8366B785927C3uLL, 0x1E);
                n0x77_2 = 0x77;
                break;
            case 0x77:
                v270 = v269 + 0x39B39BF2411BD27CLL;
                n2 = 0x78;
                break;
            case 0x78:
                v101 = (v100 ^ dword_180281E5D ^ 0x6B035F3E) - 0x4CC071E0;
                n2 = 0x79;
                break;
            case 0x79:
                v51 = __ROL4__(__ROL4__(v101, 0x17) ^ 0xFCAB611B, 0xD);
                n2 = 0x7A;
                break;
            case 0x7A:
                sub_1801865F0(&v51, 0x44, 0x17, 0x50);
                v271 = v270 * v51;
                n2 = 0x7B;
                break;
            case 0x7B:
                v272 = (v271 + 0x1D77793ED61877F5LL) ^ 0x93C2A5CE938FE832uLL;
                n2 = 0x7C;
                break;
            case 0x7C:
                v165 = v272;
                sub_1800E3F00(0x22, 0x32, &v165, 0x63);
                v273 = __ROL8__(v165, 7);
                n2 = 0x7D;
                break;
            case 0x7D:
                v274 = v273 + 0x66CA5D084149E18LL;
                v67 = 0x9F69A3D5;
                v102 = 0x9F69A3D5;
                n2 = 0x7E;
                break;
            case 0x7E:
                v103 = __ROL4__(__ROL4__(v102, 0xC) + 0x7F5FA08E, 0xE) ^ 0x3EA1067F;
                n2 = 0x7F;
                break;
            case 0x7F:
                n2 = 0x80;
                break;
            case 0x80:
                v275 = qword_180281B8D;
                v276 = (v274 ^ qword_180281B8D ^ 0x94664E8AAB847C93uLL) - 0x66CA5D084149E18LL;
                n2 = 0x81;
                break;
            case 0x81:
                v167 = __ROL8__(v276, 0x39);
                sub_18007FE10(0x36, 0x52, 0x2B, &v167);
                v277 = v167;
                n2 = 0x82;
                break;
            case 0x82:
                v278 = ((v277 ^ 0x93C2A5CE938FE832uLL) - 0x1D77793ED61877F5LL) >> v103;
                n2 = 0x83;
                break;
            case 0x83:
                v166 = (v278 + 0x1D77793ED61877F5LL) ^ 0x93C2A5CE938FE832uLL;
                n2 = 0x84;
                break;
            case 0x84:
                sub_1800E3F00(0x33, 0x5D, &v166, 0x3F);
                v279 = __ROL8__(v166, 7) + 0x66CA5D084149E18LL;
                n2 = 0x85;
                break;
            case 0x85:
                v280 = v275 ^ v279 ^ 0x94664E8AAB847C93uLL;
                n2 = 0x86;
                break;
            case 0x86:
                v168 = __ROL8__(v280 - 0x66CA5D084149E18LL, 0x39);
                sub_18007FE10(0x49, 0x4D, 0x31, &v168);
                n2 = 0x87;
                break;
            case 0x87:
                v104 = v168 ^ 0x938FE832;
                n2 = 0x88;
                break;
            case 0x88:
                v105 = __ROL4__(v104 + 0x3868C294, 0x1D);
                n2 = 0x89;
                break;
            case 0x89:
                v106 = v105 ^ 0x58687F7;
                v47 = v105 ^ 0x58687F7u;
                v281 = BYTE3(v47);
                n2 = 0x8A;
                break;
            case 0x8A:
                v107 = p_InLoadOrderModuleList_6[v281 & 0xF] << 0x18;
                n2 = 0x8B;
                break;
            case 0x8B:
                v35 = v106;
                v108 = v107 | p_InLoadOrderModuleList_6[v106 & 0xF];
                n2 = 0x8C;
                break;
            case 0x8C:
                v282 = v47 >> 0x10;
                v283 = &p_InLoadOrderModuleList_6[((unsigned int)v47 >> 0x14) & 0xF];
                n2 = 0x8D;
                break;
            case 0x8D:
                v109 = v108 | (*v283 << 0x14);
                n2 = 0x8E;
                break;
            case 0x8E:
                v110 = v109 | (p_InLoadOrderModuleList_6[v282 & 0xF] << 0x10);
                n2 = 0x8F;
                break;
            case 0x8F:
                v284 = v47 >> 8;
                v111 = v110 | (p_InLoadOrderModuleList_6[(unsigned __int16)v47 >> 0xC] << 0xC);
                n2 = 0x90;
                break;
            case 0x90:
                v112 = v111 | (p_InLoadOrderModuleList_6[v284 & 0xF] << 8);
                n2 = 0x91;
                break;
            case 0x91:
                v113 = p_InLoadOrderModuleList_6[v35 >> 4];
                n2 = 0x92;
                break;
            case 0x92:
                v114 = v112 | (0x10 * v113);
                v115 = p_InLoadOrderModuleList_6[v47 >> 0x1C];
                n2 = 0x93;
                break;
            case 0x93:
                v55 = (__ROL4__(v114 | (v115 << 0x1C), 6) ^ 0x238F0F50) + 0x29D0E15;
                n2 = 0x94;
                break;
            case 0x94:
                sub_1800D0EB0(0x26, &v55, 0x14, 0xC);
                v116 = v55;
                n2 = 0x95;
                break;
            case 0x95:
                v56 = v116;
                n2 = 0x96;
                break;
            case 0x96:
                sub_1801EEDD0(&v56, 0x3D, 0x3B, 0x3A);
                v117 = (v56 - 0x29D0E15) ^ 0x238F0F50;
                n2 = 0x97;
                break;
            case 0x97:
                v118 = __ROL4__(v117, 0x1A);
                v48 = v118;
                v285 = HIBYTE(v118) & 0xF;
                n2 = 0x98;
                break;
            case 0x98:
                v119 = p_InLoadOrderModuleList_2[v285] << 0x18;
                HIBYTE(n0x77_2) = v118;
                n2 = 0x99;
                break;
            case 0x99:
                v120 = v119 | p_InLoadOrderModuleList_2[HIBYTE(n0x77_2) & 0xF];
                n2 = 0x9A;
                break;
            case 0x9A:
                v286 = v48 >> 0x10;
                v121 = p_InLoadOrderModuleList_2[((unsigned int)v48 >> 0x14) & 0xF];
                n2 = 0x9B;
                break;
            case 0x9B:
                v122 = v120 | (v121 << 0x14);
                v287 = &p_InLoadOrderModuleList_2[v286 & 0xF];
                n2 = 0x9C;
                break;
            case 0x9C:
                v123 = v122 | (*v287 << 0x10);
                n2 = 0x9D;
                break;
            case 0x9D:
                v288 = v48 >> 8;
                v124 = v123 | (p_InLoadOrderModuleList_2[(unsigned __int16)v48 >> 0xC] << 0xC);
                n2 = 0x9E;
                break;
            case 0x9E:
                v125 = p_InLoadOrderModuleList_2[v288 & 0xF] << 8;
                n2 = 0x9F;
                break;
            case 0x9F:
                v126 = v125 | v124;
                v36 = p_InLoadOrderModuleList_2[HIBYTE(n0x77_2) >> 4];
                n2 = 0xA0;
                break;
            case 0xA0:
                v127 = v126 | (0x10 * v36);
                v289 = &p_InLoadOrderModuleList_2[v48 >> 0x1C];
                n2 = 0xA1;
                break;
            case 0xA1:
                v128 = __ROL4__(dword_180281E0F ^ (v127 | (*v289 << 0x1C)), 3);
                n2 = 0xA2;
                break;
            case 0xA2:
                v129 = v128 - 0xE813A89;
                n2 = 0xA3;
                break;
            case 0xA3:
                v290 = v256;
                v57 = v129 ^ 0xDA41153F;
                sub_1800C24E0(0x3D, 0x29, 0x34, &v57);
                n2 = 0xA4;
                break;
            case 0xA4:
                v130 = __ROL4__(__ROL4__(v57 ^ 0xC5B1C838, 0xD) + 0x61AAFA18, 5);
                n2 = 0xA5;
                break;
            case 0xA5:
                n0xA = 0x5F;
                sub_180096B30(v290 + 0x10, 0x20, v130, 3);
                n2 = 0xA6;
                break;
            case 0xA6:
                v291 = n0x72 ^ 0x72;
                n2 = 0xA7;
                break;
            case 0xA7:
                v159 = v291;
                sub_1800A91F0(0x51, &v159);
                v44 = __ROL8__(v159, 0x35) - 0x565D6B6FAFF7EB35LL;
                n2 = 0xA8;
                break;
            case 0xA8:
                v292 = HIWORD(v44);
                v37 = p_InLoadOrderModuleList_5[(v44 >> 0x34) & 0xF];
                n2 = 0xA9;
                break;
            case 0xA9:
                v293 = (unsigned __int64)v37 << 0x34;
                v294 = v44 >> 0x18;
                v295 = (unsigned int)v44 >> 0x1C;
                n2 = 0xAA;
                break;
            case 0xAA:
                v296 = v293 | ((unsigned __int64)p_InLoadOrderModuleList_5[v295] << 0x1C);
                n2 = 0xAB;
                break;
            case 0xAB:
                v297 = v296 | (p_InLoadOrderModuleList_5[BYTE2(v44) & 0xF] << 0x10);
                n2 = 0xAC;
                break;
            case 0xAC:
                v298 = p_InLoadOrderModuleList_5[((unsigned int)v44 >> 0x14) & 0xF] << 0x14;
                n2 = 0xAD;
                break;
            case 0xAD:
                v299 = v298 | v297;
                v300 = p_InLoadOrderModuleList_5[v44 & 0xF];
                n2 = 0xAE;
                break;
            case 0xAE:
                v301 = v300 | v299;
                v302 = &p_InLoadOrderModuleList_5[HIBYTE(v44) & 0xF];
                n2 = 0xAF;
                break;
            case 0xAF:
                v303 = v301 | ((unsigned __int64)*v302 << 0x38);
                v304 = v44 >> 8;
                v305 = v44 >> 0xC;
                n2 = 0xB0;
                break;
            case 0xB0:
                v306 = v303 | (p_InLoadOrderModuleList_5[v305 & 0xF] << 0xC);
                n2 = 0xB1;
                break;
            case 0xB1:
                v307 = HIDWORD(v44);
                v38 = p_InLoadOrderModuleList_5[(v44 >> 0x24) & 0xF];
                n2 = 0xB2;
                break;
            case 0xB2:
                v308 = v306 | ((unsigned __int64)v38 << 0x24);
                v309 = &p_InLoadOrderModuleList_5[v294 & 0xF];
                n2 = 0xB3;
                break;
            case 0xB3:
                v310 = v308 | (*v309 << 0x18);
                v311 = (unsigned __int8)v44 >> 4;
                n2 = 0xB4;
                break;
            case 0xB4:
                v312 = v310 | (0x10 * (unsigned int)p_InLoadOrderModuleList_5[v311]);
                n2 = 0xB5;
                break;
            case 0xB5:
                v313 = v312 | ((unsigned __int64)p_InLoadOrderModuleList_5[v292 & 0xF] << 0x30);
                n2 = 0xB6;
                break;
            case 0xB6:
                v314 = v44 >> 0x28;
                v315 = v313
                     | ((unsigned __int64)p_InLoadOrderModuleList_5[(v44 >> 0x2C) & 0xF] << 0x2C);
                n2 = 0xB7;
                break;
            case 0xB7:
                v316 = p_InLoadOrderModuleList_5[v304 & 0xF] << 8;
                n2 = 0xB8;
                break;
            case 0xB8:
                v317 = v316 | v315;
                v318 = p_InLoadOrderModuleList_5[v314 & 0xF];
                n2 = 0xB9;
                break;
            case 0xB9:
                v319 = v317 | (v318 << 0x28);
                v39 = p_InLoadOrderModuleList_5[v307 & 0xF];
                n2 = 0xBA;
                break;
            case 0xBA:
                v320 = v319 | ((unsigned __int64)v39 << 0x20);
                v321 = &p_InLoadOrderModuleList_5[v44 >> 0x3C];
                n2 = 0xBB;
                break;
            case 0xBB:
                v322 = qword_180281B27 ^ __ROL8__(v320 | ((unsigned __int64)*v321 << 0x3C), 0x3D);
                n2 = 0xBC;
                break;
            case 0xBC:
                v323 = v322 ^ 0x8F37476A75A49085uLL;
                n2 = 0xBD;
                break;
            case 0xBD:
                v131 = __ROL4__(v97 ^ 0xC82F00E4, 1);
                n2 = 0xBE;
                break;
            case 0xBE:
                v324 = v323;
                v53 = v131 ^ 0xDC994C41;
                n2 = 0xBF;
                break;
            case 0xBF:
                sub_18013CC60(0xE, 0xC, 0x1B, &v53);
                v132 = v53 - 0x425E0292;
                v325 = v324 + 0x5C;
                n2 = 0xC0;
                break;
            case 0xC0:
                n0xA = 0x32;
                sub_180096B30(v325, 0x28, v132, 6);
                n2 = 0x11;
                break;
            case 0xC1:
                v8 = (__int64 *)sub_180143A00(0x2A, 0x5C, v45, 0xF);
                v173 = *v8;
                v326 = v8 + 2;
                v327 = (_DWORD *)(v8[2] + 0x2C);
                n2 = 0xC2;
                break;
            case 0xC2:
                v133 = (*v327 + 0x3F16914D) ^ 0xA7F45DB;
                n2 = 0xC3;
                break;
            case 0xC3:
                v58 = __ROL4__(v133, 0x1A);
                sub_1800E4370(0x40, 0x5B, &v58, 0x2F);
                n2 = 0xC4;
                break;
            case 0xC4:
                v62 = __ROL4__(v72 ^ v58 ^ 0xD, 0xB);
                n2 = 0xC5;
                break;
            case 0xC5:
                v66 = v62;
                v328 = HIBYTE(v62);
                v329 = &p_InLoadOrderModuleList_7[v62 >> 0x1C];
                n2 = 0xC6;
                break;
            case 0xC6:
                v330 = (unsigned __int64)*v329 << 0x1C;
                v14 = v62;
                n2 = 0xC7;
                break;
            case 0xC7:
                v331 = v330 | p_InLoadOrderModuleList_7[v14 & 0xF];
                n2 = 0xC8;
                break;
            case 0xC8:
                v332 = v331 | (p_InLoadOrderModuleList_7[BYTE2(v66) & 0xF] << 0x10);
                n2 = 0xC9;
                break;
            case 0xC9:
                v333 = 0x10 * (unsigned int)p_InLoadOrderModuleList_7[v14 >> 4];
                n2 = 0xCA;
                break;
            case 0xCA:
                v334 = v333 | v332;
                v40 = p_InLoadOrderModuleList_7[((unsigned int)v66 >> 0x14) & 0xF];
                n2 = 0xCB;
                break;
            case 0xCB:
                v335 = v334 | (v40 << 0x14);
                v336 = ((unsigned int)v66 >> 8) & 0xF;
                n2 = 0xCC;
                break;
            case 0xCC:
                v337 = v335 | (p_InLoadOrderModuleList_7[v336] << 8);
                v338 = v66 >> 0xC;
                n2 = 0xCD;
                break;
            case 0xCD:
                v339 = v337 | (p_InLoadOrderModuleList_7[v338 & 0xF] << 0xC);
                n2 = 0xCE;
                break;
            case 0xCE:
                v340 = v339 | (p_InLoadOrderModuleList_7[v328 & 0xF] << 0x18);
                n2 = 0xCF;
                break;
            case 0xCF:
                v174 = *(int **)(v173 + (unsigned int)(v340 - 0x4534744A));
                n2 = 0xD0;
                break;
            case 0xD0:
                n2 = 0xD1;
                break;
            case 0xD1:
                v7 = *v174;
                v134 = 0xCC9E2D51 * *v174;
                v135 = 0x16A88000 * v7;
                n2 = 0xD2;
                break;
            case 0xD2:
                v136 = 5 * __ROL4__(0x1B873593 * (v135 | (v134 >> 0x11)), 0xD);
                n2 = 0xD3;
                break;
            case 0xD3:
                v137 = v136 - 0x19AB949C;
                v138 = v174[1];
                n2 = 0xD4;
                break;
            case 0xD4:
                v139 = 0x16A88000 * v138;
                v140 = (0xCC9E2D51 * v138) >> 0x11;
                n2 = 0xD5;
                break;
            case 0xD5:
                v141 = v137 ^ (0x1B873593 * (v139 | v140));
                n2 = 0xD6;
                break;
            case 0xD6:
                v142 = 5 * __ROL4__(v141, 0xD) - 0x19AB949C;
                n2 = 0xD7;
                break;
            case 0xD7:
                v143 = 0x85EBCA6B * (v142 ^ HIWORD(v142) ^ 8);
                n2 = 0xD8;
                break;
            case 0xD8:
                v144 = (0xC2B2AE35 * (v143 ^ (v143 >> 0xD)))
                     ^ ((0xC2B2AE35 * (v143 ^ (v143 >> 0xD))) >> 0x10);
                n2 = 0xD9;
                break;
            case 0xD9:
                if ( (unsigned __int8)sub_1801E9A40(0x5F, *v170, 0x46, *v169, v144) )
                    n2 = 0xDF;
                else
                    n2 = 0xDA;
                break;
            case 0xDA:
                n2 = 0xDB;
                break;
            case 0xDB:
                LOBYTE(n0x77_2) = 0;
                sub_1801C72D0(0x31, 0x12, 0x64, &n0x77_2);
                v15 = n0x77_2 + 0x3A;
                n2 = 0xDC;
                break;
            case 0xDC:
                v41 = 0x10 * p_InLoadOrderModuleList_8[v15 >> 4];
                n2 = 0xDD;
                break;
            case 0xDD:
                v42 = p_InLoadOrderModuleList_8[v15 & 0xF] | v41;
                n2 = 0xDE;
                break;
            case 0xDE:
                v17 = v42;
                n2 = 0xC;
                break;
            case 0xDF:
                v145 = *(_DWORD *)(*v326 + 0x44LL);
                n2 = 0xE0;
                break;
            case 0xE0:
                v59 = v145 ^ 0xBE343DD0;
                sub_1801E63E0(3, &v59, 0x18, 0x17);
                v146 = v59;
                n2 = 0xE1;
                break;
            case 0xE1:
                v63 = __ROL4__(v73 ^ v146, 3) - 0x6C873F15;
                v49 = v63;
                n2 = 0xE2;
                break;
            case 0xE2:
                v341 = v49 >> 8;
                v342 = (unsigned __int8 *)&loc_18022725F + ((unsigned __int16)v49 >> 0xC) + 1;
                n2 = 0xE3;
                break;
            case 0xE3:
                v343 = *v342 << 0xC;
                v344 = v49 >> 0x10;
                v345 = v49 >> 0x14;
                n2 = 0xE4;
                break;
            case 0xE4:
                v346 = v343 | (*((unsigned __int8 *)&loc_18022725F + (v345 & 0xF) + 1) << 0x14);
                n2 = 0xE5;
                break;
            case 0xE5:
                v347 = *((unsigned __int8 *)&loc_18022725F + (BYTE3(v49) & 0xF) + 1) << 0x18;
                n2 = 0xE6;
                break;
            case 0xE6:
                v348 = v347 | v346;
                v349 = (unsigned __int8 *)&loc_18022725F + (v341 & 0xF) + 1;
                n2 = 0xE7;
                break;
            case 0xE7:
                v350 = v348 | (*v349 << 8);
                v16 = v63;
                n2 = 0xE8;
                break;
            case 0xE8:
                v351 = v350 | *((unsigned __int8 *)&loc_18022725F + (v16 & 0xF) + 1);
                n2 = 0xE9;
                break;
            case 0xE9:
                v352 = v351
                     | ((unsigned __int64)*((unsigned __int8 *)&loc_18022725F + (v49 >> 0x1C) + 1) << 0x1C);
                n2 = 0xEA;
                break;
            case 0xEA:
                v353 = *((unsigned __int8 *)&loc_18022725F + (v344 & 0xF) + 1) << 0x10;
                n2 = 0xEB;
                break;
            case 0xEB:
                v354 = v353 | v352;
                v355 = v16 >> 4;
                n2 = 0xEC;
                break;
            case 0xEC:
                v356 = (v354 | (0x10 * (unsigned int)*((unsigned __int8 *)&loc_18022725F + v355 + 1)))
                     + 0xF064BD4D;
                n2 = 0xED;
                break;
            case 0xED:
                v175 = *(int **)(v173 + ((unsigned int)v356 ^ 0xACLL));
                n2 = 0xEE;
                break;
            case 0xEE:
                n2 = 0xEF;
                break;
            case 0xEF:
                v6 = *v175;
                v147 = 0xCC9E2D51 * *v175;
                v148 = 0x16A88000 * v6;
                n2 = 0xF0;
                break;
            case 0xF0:
                v149 = __ROL4__(0x1B873593 * (v148 | (v147 >> 0x11)), 0xD);
                n2 = 0xF1;
                break;
            case 0xF1:
                v150 = 5 * v149 - 0x19AB949C;
                v357 = v175 + 1;
                n2 = 0xF2;
                break;
            case 0xF2:
                v5 = *v357;
                v151 = 0xCC9E2D51 * *v357;
                v152 = 0x16A88000 * v5;
                n2 = 0xF3;
                break;
            case 0xF3:
                v153 = v150 ^ (0x1B873593 * (v152 | (v151 >> 0x11)));
                n2 = 0xF4;
                break;
            case 0xF4:
                v154 = 5 * __ROL4__(v153, 0xD) - 0x19AB949C;
                n2 = 0xF5;
                break;
            case 0xF5:
                v155 = v154 ^ HIWORD(v154) ^ 8;
                n2 = 0xF6;
                break;
            case 0xF6:
                v156 = (0xC2B2AE35 * ((0x85EBCA6B * v155) ^ ((0x85EBCA6B * v155) >> 0xD)))
                     ^ ((0xC2B2AE35 * ((0x85EBCA6B * v155) ^ ((0x85EBCA6B * v155) >> 0xD))) >> 0x10);
                n2 = 0xF7;
                break;
            case 0xF7:
                v4 = sub_1801E9A40(0x1B, *v170, 0x3A, *v169, v156);
                v64 = v45 + 1;
                if ( v4 )
                    n2 = 0xB;
                else
                    n2 = 0xDA;
                break;
            default:
                continue;
        }
    }
}
"""
IDA_MICROCODE_MMAT_LOCOPT = """
0. 0 ; STKD=0 MINREF=0/END=8D8 ARGS: OFF=900/MINREF=8E0/END=AE0/SHADOW=20
0. 0 ; SAVEDREGS: r15.8,r14.8,r13.8,r12.8,rsi.8,rdi.8,rbp.8,rbx.8
0. 0 ; 1WAY-BLOCK 0 FAKE OUTBOUNDS: 1 [START=18000A3C0 END=18000A3C0] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
0. 0 ; DEF: (rax.16,rcx.16,rsp.8,rdi.16,r12.8,r13.8,r14.8,r15.8,ds.2,sp+30.4,sp+37..48,sp+49..70,sp+74..98,sp+9C..D1,sp+D4..E8,sp+EC.4,sp+F4..111,sp+114..179,sp+17C.9,sp+188..1B5,sp+1B8..288,sp+290..2AC,sp+2B0..2E8,sp+2F0..301,sp+308.1,sp+310.9,sp+320.1,sp+328.9,sp+338.1,sp+340.9,sp+350.1,sp+358..371,sp+378.9,sp+388..3C1,sp+3C8.9,sp+3D8.9,sp+3E8..411,sp+418..469,sp+470..481,sp+488..499,sp+4A0..4C9,sp+4D0..4E1,sp+4E8..521,sp+528..631,sp+638.1,sp+640.9,sp+650.9,sp+660.9,sp+670..689,sp+690.9,sp+6A0..6E9,sp+6F0.1,sp+6F8.9,sp+708..739,sp+740..7A9,sp+7B0..7F9,sp+800.C,sp+810.1,sp+818..829,sp+830.1,sp+838..88C,sp+890.8,180281ADF.4,180281B27.8,180281B8D.8,180281BE0.8,180281BFA.4,180281C94.1,180281CB4.8,180281D52.4,180281E0F.4,180281E5D.4,180284078.8,1802847D8.8)
0. 0
1. 0 ; 1WAY-BLOCK 1 INBOUNDS: 0 OUTBOUNDS: 3 [START=18000A3C0 END=18000A426] MINREFS: STK=0/ARG=8E0, MAXBSP: 898
1. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rbx.8,rdi.16,r12.8,r13.8,r14.8,r15.8,sp+30.4
1. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rbx.8,rdi.16,r12.8,r13.8,r14.8,r15.8
1. 0 mov    #0.1, cf.1              ; 18000A3CC u=           d=cf.1
1. 1 mov    #0.1, zf.1              ; 18000A3CC u=           d=zf.1
1. 2 mov    #0.1, of.1              ; 18000A3CC u=           d=of.1
1. 3 und    sf.1                    ; 18000A3CC u=           d=sf.1
1. 4 und    pf.1                    ; 18000A3CC u=           d=pf.1
1. 5 mov    #-0x565D6B6FAFF7EB35.8, rdi.8 ; 18000A3D3 u=           d=rdi.8
1. 6 mov    #-0x6C3D5A316C7017CE.8, r15.8 ; 18000A3DD u=           d=r15.8
1. 7 mov    #-0x70C8B8958A5B6F7B.8, r12.8 ; 18000A3E7 u=           d=r12.8
1. 8 mov    #0x7DC53AF5F68B1802.8, r13.8 ; 18000A3F1 u=           d=r13.8
1. 9 mov    #0x1D77793ED61877F5.8, rsi.8 ; 18000A3FB u=           d=rsi.8
1.10 mov    #0x66CA5D084149E18.8, rbx.8 ; 18000A405 u=           d=rbx.8
1.11 mov    #0xBACB8BB6.8, r14.8    ; 18000A40F u=           d=r14.8
1.12 mov    #0.4, %var_8A8.4        ; 18000A415 u=           d=sp+30.4
1.13 goto   @3                      ; 18000A424 u=
1.13
2. 0 ; 1WAY-BLOCK 2 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A426 END=18000A440] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
2. 0 ; DEF: sp+30.4,sp+EC.4
2. 0 mov    #0xF52F742A.4, %var_7EC.4 ; 18000A426 u=           d=sp+EC.4
2. 1 mov    #8.4, %var_8A8.4        ; 18000A431 u=           d=sp+30.4
2. 1
3. 0 ; 1WAY-BLOCK 3 INBOUNDS: 1 2 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 23 24 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 43 44 45 46 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 82 83 85 86 88 89 90 91 92 93 95 96 97 98 99 100 101 102 103 104 105 106 107 108 109 110 111 113 114 115 116 117 119 121 122 123 124 125 126 127 128 129 130 131 132 133 136 137 138 139 140 141 142 143 144 146 147 148 149 151 152 155 156 157 158 159 160 161 162 163 164 165 166 167 168 169 170 171 172 173 176 177 179 181 182 183 184 185 186 187 188 189 190 191 193 194 195 197 198 199 200 201 202 204 206 207 208 209 210 212 214 215 216 217 219 220 221 222 224 225 226 227 228 229 230 231 232 233 234 235 236 237 238 240 241 242 243 244 245 246 247 248 249 251 253 255 256 257 259 261 262 263 264 265 266 267 268 269 270 271 273 274 275 276 277 278 279 280 281 282 283 284 286 287 290 291 292 293 294 295 296 OUTBOUNDS: 4 [START=18000A440 END=18000A44C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
3. 0 ; USE: sp+30.4
3. 0 ; DEF: rax.8
3. 0 ; DNU: rax.8
3. 0 xdu    %var_8A8.4, rax.8       ; 18000A440 u=sp+30.4    d=rax.8
3. 0
4. 0 ; NWAY-BLOCK 4 INBOUNDS: 3 OUTBOUNDS: 2 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 24 25 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 44 45 46 47 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 83 84 86 87 89 90 91 92 93 94 96 97 98 99 100 101 102 103 104 105 106 107 108 109 110 111 112 114 115 116 117 118 120 122 123 124 125 126 127 128 129 130 131 132 133 134 137 138 139 140 141 142 143 144 145 147 148 149 150 152 153 156 157 158 159 160 161 162 163 164 165 166 167 168 169 170 171 172 173 174 177 178 180 182 183 184 185 186 187 188 189 190 191 192 194 195 196 198 199 200 201 202 203 205 207 208 209 210 211 213 215 216 217 218 220 221 222 223 225 226 227 228 229 230 231 232 233 234 235 236 237 238 239 241 242 243 244 245 246 247 248 249 250 252 254 256 257 258 260 262 263 264 265 266 267 268 269 270 271 272 274 275 276 277 278 279 280 281 282 283 284 285 287 288 291 3 [START=18000A44C END=18000A456] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
4. 0 ; USE: rax.8
4. 0 jtbl   rax.8, {7 => 2, 0 => 5, 8 => 6, 0xA => 7, 0x19 => 8, 0xE => 9, 0x18 => 10, 0x1B => 11, 0x3A => 12, 0x43 => 13, 0x26 => 14, 0x25 => 15, 0x28 => 16, 0x51 => 17, 0x2C => 18, 0x35 => 19, 0x38 => 20, 0x48 => 21, 0x74 => 24, 0x7C => 25, 0x42 => 27, 0x5A => 28, 0x73 => 29, 1 => 30, 0x17 => 31, 0x3F => 32, 0x1A => 33, 0x44 => 34, 0x62 => 35, 0x64 => 36, 0x89 => 37, 0x6D => 38, 0x3D => 39, 0x7D => 40, 0x4E => 41, 0xA3 => 42, 0x40 => 44, 0x57 => 45, 0x8A => 46, 0x6E => 47, 0x50 => 49, 0xA4 => 50, 0x9C => 51, 0x8D => 52, 0x13 => 53, 0x24 => 54, 0x58 => 55, 0x23 => 56, 0x5B => 57, 0xA8 => 58, 0x7F => 59, 0x97 => 60, 0x8E => 61, 0xB1 => 62, 0x5C => 63, 0x4F => 64, 0xAA => 65, 0x5F => 66, 0x9A => 67, 0xC5 => 68, 0x39 => 69, 0x46 => 70, 0x9F => 71, 0x2A => 72, 0xCC => 73, 0x91 => 74, 0x14 => 75, 0x20 => 76, 0x56 => 77, 0x4D => 78, 0x60 => 79, 0x85 => 80, 0x68 => 81, 0x8B => 83, 0x86 => 84, 0xB5 => 86, 0xA7 => 87, 0xB0 => 89, 0xD2 => 90, 0xC2 => 91, 0x8C => 92, 0xC8 => 93, 0xBF => 94, 0xAC => 96, 0xD4 => 97, 0xD3 => 98, 0x6C => 99, 0x63 => 100, 0xB2 => 101, 0xDC => 102, 0xD5 => 103, 0x70 => 104, 0x75 => 105, 0xE7 => 106, 0xB4 => 107, 0xC => 108, 0xCB => 109, 0xE9 => 110, 0xD6 => 111, 0x47 => 112, 0xC7 => 114, 0x82 => 115, 0x2B => 116, 0xBD => 117, 0x76 => 118, 0xA5 => 120, 0xEC => 122, 0x7E => 123, 0xA6 => 124, 0xC6 => 125, 0xF3 => 126, 0xCF => 127, 0x78 => 128, 0xBB => 129, 0xB7 => 130, 0xEB => 131, 0x3E => 132, 0xEE => 133, 0x11 => 134, 0x1F => 137, 0xDE => 138, 0x32 => 139, 0xDF => 140, 0xF5 => 141, 0x5E => 142, 0x61 => 143, 0xE8 => 144, 0x7A => 145, 0xB8 => 147, 0xF4 => 148, 0xF0 => 149, 0xF => 150, 0xF6 => 152, 0xF7 => 153, 0x9B => 156, 0x95 => 157, 0xD8 => 158, 0xE6 => 159, 0x99 => 160, 0xCE => 161, 0xAB => 162, 0xE3 => 163, 0xBA => 164, 0xF2 => 165, 0xB6 => 166, 0xB9 => 167, 0xE2 => 168, 0xEA => 169, 0xF1 => 170, 0xE5 => 171, 0xED => 172, 0xEF => 173, 0xD9 => 174, 0xD7 => 177, 0x16 => 178, 0x10 => 180, 0x21 => 182, 0x4C => 183, 0xCA => 184, 0x4A => 185, 0x67 => 186, 0x79 => 187, 0x77 => 188, 0xA2 => 189, 0xE1 => 190, 0xA1 => 191, 0x84 => 192, 0x80 => 194, 0x87 => 195, 0x81 => 196, 0xD0 => 198, 0xE4 => 199, 0xBE => 200, 0xCD => 201, 0xBC => 202, 0xE0 => 203, 0xDB => 205, 0xDA => 207, 0x83 => 208, 0xD1 => 209, 0xDD => 210, 0xC1 => 211, 0x66 => 213, 0x88 => 215, 0x6F => 216, 0xAF => 217, 0xC0 => 218, 0x31 => 220, 0x49 => 221, 0x7B => 222, 0xC3 => 223, 0xC9 => 225, 0xAE => 226, 0x69 => 227, 0xA0 => 228, 0xAD => 229, 0x8F => 230, 0xC4 => 231, 0x90 => 232, 0xA9 => 233, 0x92 => 234, 0x29 => 235, 0xB3 => 236, 0x5D => 237, 0x98 => 238, 0x2E => 239, 0x93 => 241, 0x2D => 242, 0x71 => 243, 0x9D => 244, 0x9E => 245, 0x6A => 246, 0x34 => 247, 0x33 => 248, 0x65 => 249, 0x96 => 250, 0x30 => 252, 0x4B => 254, 0x55 => 256, 0x2F => 257, 0x72 => 258, 0x94 => 260, 0x37 => 262, 9 => 263, 0x41 => 264, 0x45 => 265, 5 => 266, 0x3B => 267, 0x36 => 268, 0xD => 269, 0x3C => 270, 0x22 => 271, 0x6B => 272, 0x1C => 274, 0x53 => 275, 0x59 => 276, 0x27 => 277, 2 => 278, 0x54 => 279, 0x52 => 280, 0x15 => 281, 6 => 282, 0x1D => 283, 0x1E => 284, 3 => 285, 0x12 => 287, 0xB => 288, 4 => 291, def => 3} ; 18000A454 u=rax.8
4. 0
5. 0 ; 1WAY-BLOCK 5 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A456 END=18000A460] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
5. 0 ; DEF: sp+30.4
5. 0 mov    #1.4, %var_8A8.4        ; 18000A456 u=           d=sp+30.4
5. 1 goto   @3                      ; 18000A45E u=
5. 1
6. 0 ; 1WAY-BLOCK 6 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A460 END=18000A543] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
6. 0 ; USE: sp+EC.4
6. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+F4.4
6. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
6. 0 setz   (%var_7EC.4+#0x22F1E3F2.4), #0.4, zf.1 ; 18000A4D5 u=sp+EC.4    d=zf.1
6. 1 setp   (%var_7EC.4+#0x22F1E3F2.4), #0.4, pf.1 ; 18000A4D5 u=sp+EC.4    d=pf.1
6. 2 sets   (%var_7EC.4+#0x22F1E3F2.4), sf.1 ; 18000A4D5 u=sp+EC.4    d=sf.1
6. 3 mov    call !__ROL4__<fast:_DWORD (%var_7EC.4+#0x22F1E3F2.4),char #0x16.1>.4, eax.4 ; 18000A4DA u=sp+EC.4    d=eax.4
6. 4 cfshl  (%var_7EC.4+#0x22F1E3F2.4), #0x16.1, cf.1 ; 18000A4DA u=sp+EC.4    d=cf.1
6. 5 und    of.1                    ; 18000A4DA u=           d=of.1
6. 6 xdu    eax.4, rax.8            ; 18000A4DA u=eax.4      d=rax^4.4
6. 7 mov    eax.4, %var_7E4.4       ; 18000A4DD u=eax.4      d=sp+F4.4
6. 8 mov    #9.4, %var_8A8.4        ; 18000A536 u=           d=sp+30.4
6. 9 goto   @3                      ; 18000A53E u=
6. 9
7. 0 ; 1WAY-BLOCK 7 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A543 END=18000A5E8] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
7. 0 ; USE: sp+F8.4,180281ADF.4,180281D52.4,180284078.8
7. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+D4.4,sp+FC.8,sp+2B0..2C0
7. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
7. 0 mov    $qword_180281ADF.4, %var_7DC.4 ; 18000A5A1 u=180281ADF.4 d=sp+FC.4
7. 1 add    $qword_180284078.8, #8.8, rcx.8 ; 18000A5A8 u=180284078.8 d=rcx.8
7. 2 add    $qword_180284078.8, #8.8, %var_628.8 ; 18000A5AC u=180284078.8 d=sp+2B0.8
7. 3 cfadd  $qword_180284078.8, #0x10.8, cf.1 ; 18000A5B4 u=180284078.8 d=cf.1
7. 4 ofadd  #0x10.8, $qword_180284078.8, of.1 ; 18000A5B4 u=180284078.8 d=of.1
7. 5 setz   ($qword_180284078.8+#0x10.8), #0.8, zf.1 ; 18000A5B4 u=180284078.8 d=zf.1
7. 6 setp   ($qword_180284078.8+#0x10.8), #0.8, pf.1 ; 18000A5B4 u=180284078.8 d=pf.1
7. 7 sets   ($qword_180284078.8+#0x10.8), sf.1 ; 18000A5B4 u=180284078.8 d=sf.1
7. 8 add    $qword_180284078.8, #0x10.8, %var_620.8 ; 18000A5B8 u=180284078.8 d=sp+2B8.8
7. 9 mov    $dword_180281D52.4, %var_7D8.4 ; 18000A5C6 u=180281D52.4 d=sp+100.4
7.10 xdu    %var_7E0.4, rax.8       ; 18000A5CD u=sp+F8.4    d=rax.8
7.11 mov    %var_7E0.4, %var_804.4  ; 18000A5D4 u=sp+F8.4    d=sp+D4.4
7.12 mov    #0xB.4, %var_8A8.4      ; 18000A5DB u=           d=sp+30.4
7.13 goto   @3                      ; 18000A5E3 u=
7.13
8. 0 ; 1WAY-BLOCK 8 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A5E8 END=18000A622] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
8. 0 ; USE: ds.2,sp+78.8,(GLBLOW,sp+0..78,sp+80..,SHADOW,ARGS,GLBHIGH)
8. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+118.4,sp+308.8
8. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
8. 0 shr    %var_860.8, #0x18.1, %var_5D0.8 ; 18000A5F4 u=sp+78.8    d=sp+308.8
8. 1 mov    &($p_InLoadOrderModuleList_10).8, rcx.8 ; 18000A600 u=           d=rcx.8
8. 2 xdu    [ds.2:((%var_860.8 >>l #0x1C.1)+&($p_InLoadOrderModuleList_10).8)].1, eax.4 ; 18000A607 u=ds.2,sp+78.8,(GLBLOW,sp+0..78,sp+80..,SHADOW,ARGS,GLBHIGH) d=eax.4
8. 3 cfshl  eax.4, #0x1C.1, cf.1    ; 18000A60B u=eax.4      d=cf.1
8. 4 mul    #0x10000000.4, eax.4, eax.4 ; 18000A60B u=eax.4      d=eax.4
8. 5 und    of.1                    ; 18000A60B u=           d=of.1
8. 6 setz   eax.4, #0.4, zf.1       ; 18000A60B u=eax.4      d=zf.1
8. 7 setp   eax.4, #0.4, pf.1       ; 18000A60B u=eax.4      d=pf.1
8. 8 sets   eax.4, sf.1             ; 18000A60B u=eax.4      d=sf.1
8. 9 xdu    eax.4, rax.8            ; 18000A60B u=eax.4      d=rax^4.4
8.10 mov    eax.4, %var_7C0.4       ; 18000A60E u=eax.4      d=sp+118.4
8.11 mov    #0x1A.4, %var_8A8.4     ; 18000A615 u=           d=sp+30.4
8.12 goto   @3                      ; 18000A61D u=
8.12
9. 0 ; 1WAY-BLOCK 9 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A622 END=18000A655] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
9. 0 ; USE: ds.2,sp+50.1,sp+2F0.8,(GLBLOW,sp+0..50,sp+51..2F0,sp+2F8..,SHADOW,ARGS,GLBHIGH)
9. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+51.1,sp+2F8.8
9. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
9. 0 mul    #0x10.1, [ds.2:%var_5E8.8].1, %var_887.1 ; 18000A630 u=ds.2,sp+2F0.8,(GLBLOW,sp+0..2F0,sp+2F8..,SHADOW,ARGS,GLBHIGH) d=sp+51.1
9. 1 xor    xdu.8((%var_888.1 & #0xF.1)), #0xB.8, rax.8 ; 18000A63C u=sp+50.1    d=rax.8
9. 2 mov    #0.1, cf.1              ; 18000A63C u=           d=cf.1
9. 3 mov    #0.1, of.1              ; 18000A63C u=           d=of.1
9. 4 setz   (xdu.8((%var_888.1 & #0xF.1)) ^ #0xB.8), #0.8, zf.1 ; 18000A63C u=sp+50.1    d=zf.1
9. 5 setp   (xdu.8((%var_888.1 & #0xF.1)) ^ #0xB.8), #0.8, pf.1 ; 18000A63C u=sp+50.1    d=pf.1
9. 6 mov    #0.1, sf.1              ; 18000A63C u=           d=sf.1
9. 7 xor    xdu.8((%var_888.1 & #0xF.1)), #0xB.8, %var_5E0.8 ; 18000A640 u=sp+50.1    d=sp+2F8.8
9. 8 mov    #0xF.4, %var_8A8.4      ; 18000A648 u=           d=sp+30.4
9. 9 goto   @3                      ; 18000A650 u=
9. 9
10. 0 ; 1WAY-BLOCK 10 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A655 END=18000A6FF] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
10. 0 ; USE: ds.2,sp+78.8,(GLBLOW,sp+0..78,sp+80..,SHADOW,ARGS,GLBHIGH)
10. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+114.4,sp+300.8
10. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
10. 0 shr    %var_860.8, #8.1, %var_5D8.8 ; 18000A65E u=sp+78.8    d=sp+300.8
10. 1 mov    &($p_InLoadOrderModuleList_10).8, rcx.8 ; 18000A670 u=           d=rcx.8
10. 2 xdu    [ds.2:(xdu.8((%var_860.2 >>l #0xC.1))+&($p_InLoadOrderModuleList_10).8)].1, eax.4 ; 18000A6E4 u=ds.2,sp+78.2,(GLBLOW,sp+0..78,sp+7A..,SHADOW,ARGS,GLBHIGH) d=eax.4
10. 3 cfshl  eax.4, #0xC.1, cf.1     ; 18000A6E8 u=eax.4      d=cf.1
10. 4 mul    #0x1000.4, eax.4, eax.4 ; 18000A6E8 u=eax.4      d=eax.4
10. 5 und    of.1                    ; 18000A6E8 u=           d=of.1
10. 6 setz   eax.4, #0.4, zf.1       ; 18000A6E8 u=eax.4      d=zf.1
10. 7 setp   eax.4, #0.4, pf.1       ; 18000A6E8 u=eax.4      d=pf.1
10. 8 sets   eax.4, sf.1             ; 18000A6E8 u=eax.4      d=sf.1
10. 9 xdu    eax.4, rax.8            ; 18000A6E8 u=eax.4      d=rax^4.4
10.10 mov    eax.4, %var_7C4.4       ; 18000A6EB u=eax.4      d=sp+114.4
10.11 mov    #0x19.4, %var_8A8.4     ; 18000A6F2 u=           d=sp+30.4
10.12 goto   @3                      ; 18000A6FA u=
10.12
11. 0 ; 1WAY-BLOCK 11 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A6FF END=18000A796] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
11. 0 ; USE: ds.2,sp+78.8,sp+11C.4,sp+310.8,(GLBLOW,sp+0..78,sp+80..11C,sp+120..310,sp+318..,SHADOW,ARGS,GLBHIGH)
11. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+120.4,sp+318..328
11. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
11. 0 or     %var_7BC.4, xdu.4([ds.2:%var_5C8.8].1), %var_7B8.4 ; 18000A711 u=ds.2,sp+11C.4,sp+310.8,(GLBLOW,sp+0..11C,sp+120..310,sp+318..,SHADOW,ARGS,GLBHIGH) d=sp+120.4
11. 1 shr    %var_860.8, #0x10.1, %var_5C0.8 ; 18000A721 u=sp+78.8    d=sp+318.8
11. 2 cfshr  %var_860.8, #0x14.1, cf.1 ; 18000A77D u=sp+78.8    d=cf.1
11. 3 shr    %var_860.8, #0x14.1, rax.8 ; 18000A77D u=sp+78.8    d=rax.8
11. 4 und    of.1                    ; 18000A77D u=           d=of.1
11. 5 setz   (%var_860.8 >>l #0x14.1), #0.8, zf.1 ; 18000A77D u=sp+78.8    d=zf.1
11. 6 setp   (%var_860.8 >>l #0x14.1), #0.8, pf.1 ; 18000A77D u=sp+78.8    d=pf.1
11. 7 mov    #0.1, sf.1              ; 18000A77D u=           d=sf.1
11. 8 shr    %var_860.8, #0x14.1, %var_5B8.8 ; 18000A781 u=sp+78.8    d=sp+320.8
11. 9 mov    #0x1C.4, %var_8A8.4     ; 18000A789 u=           d=sp+30.4
11.10 goto   @3                      ; 18000A791 u=
11.10
12. 0 ; 1WAY-BLOCK 12 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A796 END=18000A7DB] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
12. 0 ; USE: sp+40.8,sp+56.1,sp+3C8.8
12. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+3D8..3F0
12. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
12. 0 or     %var_510.8, xdu.8((#0x1000.4*xdu.4(%var_882.1))), %var_500.8 ; 18000A7A6 u=sp+56.1,sp+3C8.8 d=sp+3D8.8
12. 1 xdu    %var_898@4.4, %var_4F8.8 ; 18000A7B2 u=sp+44.4    d=sp+3E0.8
12. 2 mov    #0.1, cf.1              ; 18000A7C3 u=           d=cf.1
12. 3 mov    #0.1, of.1              ; 18000A7C3 u=           d=of.1
12. 4 setz   (low.4((%var_898.8 >>l #0x24.1)) & #0xF.4), #0.4, zf.1 ; 18000A7C3 u=sp+40.8    d=zf.1
12. 5 setp   (low.4((%var_898.8 >>l #0x24.1)) & #0xF.4), #0.4, pf.1 ; 18000A7C3 u=sp+40.8    d=pf.1
12. 6 mov    #0.1, sf.1              ; 18000A7C3 u=           d=sf.1
12. 7 and    (%var_898.8 >>l #0x24.1), #0xF.8, rax.8 ; 18000A7C3 u=sp+40.8    d=rax.8
12. 8 and    (%var_898.8 >>l #0x24.1), #0xF.8, %var_4F0.8 ; 18000A7C6 u=sp+40.8    d=sp+3E8.8
12. 9 mov    #0x3B.4, %var_8A8.4     ; 18000A7CE u=           d=sp+30.4
12.10 goto   @3                      ; 18000A7D6 u=
12.10
13. 0 ; 1WAY-BLOCK 13 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A7DB END=18000A812] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
13. 0 ; USE: ds.2,sp+3E0.1,sp+438.8,(GLBLOW,sp+0..3E0,sp+3E1..438,sp+440..,SHADOW,ARGS,GLBHIGH)
13. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+440.8
13. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
13. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000A7E6 u=           d=rcx.8
13. 1 or     %var_4A0.8, (#0x100000000.8*xdu.8([ds.2:(xdu.8((%var_4F8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)), rax.8 ; 18000A7F5 u=ds.2,sp+3E0.1,sp+438.8,(GLBLOW,sp+0..3E0,sp+3E1..438,sp+440..,SHADOW,ARGS,GLBHIGH) d=rax.8
13. 2 mov    #0.1, cf.1              ; 18000A7F5 u=           d=cf.1
13. 3 mov    #0.1, of.1              ; 18000A7F5 u=           d=of.1
13. 4 setz   (%var_4A0.8 | (#0x100000000.8*xdu.8([ds.2:(xdu.8((%var_4F8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, zf.1 ; 18000A7F5 u=ds.2,sp+3E0.1,sp+438.8,(GLBLOW,sp+0..3E0,sp+3E1..438,sp+440..,SHADOW,ARGS,GLBHIGH) d=zf.1
13. 5 setp   (%var_4A0.8 | (#0x100000000.8*xdu.8([ds.2:(xdu.8((%var_4F8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, pf.1 ; 18000A7F5 u=ds.2,sp+3E0.1,sp+438.8,(GLBLOW,sp+0..3E0,sp+3E1..438,sp+440..,SHADOW,ARGS,GLBHIGH) d=pf.1
13. 6 sets   (%var_4A0.8 | (#0x100000000.8*xdu.8([ds.2:(xdu.8((%var_4F8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), sf.1 ; 18000A7F5 u=ds.2,sp+3E0.1,sp+438.8,(GLBLOW,sp+0..3E0,sp+3E1..438,sp+440..,SHADOW,ARGS,GLBHIGH) d=sf.1
13. 7 or     %var_4A0.8, (#0x100000000.8*xdu.8([ds.2:(xdu.8((%var_4F8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)), %var_498.8 ; 18000A7FD u=ds.2,sp+3E0.1,sp+438.8,(GLBLOW,sp+0..3E0,sp+3E1..438,sp+440..,SHADOW,ARGS,GLBHIGH) d=sp+440.8
13. 8 mov    #0x44.4, %var_8A8.4     ; 18000A805 u=           d=sp+30.4
13. 9 goto   @3                      ; 18000A80D u=
13. 9
14. 0 ; 1WAY-BLOCK 14 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A812 END=18000A8ED] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
14. 0 ; USE: sp+C8.1
14. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+53.1,sp+340.8
14. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
14. 0 mov    %var_810.1, %var_885.1  ; 18000A81A u=sp+C8.1    d=sp+53.1
14. 1 mov    #0.1, cf.1              ; 18000A81E u=           d=cf.1
14. 2 mov    #0.1, of.1              ; 18000A81E u=           d=of.1
14. 3 setz   xdu.4((%var_810.1 & #0xF.1)), #0.4, zf.1 ; 18000A81E u=sp+C8.1    d=zf.1
14. 4 setp   xdu.4((%var_810.1 & #0xF.1)), #0.4, pf.1 ; 18000A81E u=sp+C8.1    d=pf.1
14. 5 mov    #0.1, sf.1              ; 18000A81E u=           d=sf.1
14. 6 xdu    (%var_810.1 & #0xF.1), rax.8 ; 18000A81E u=sp+C8.1    d=rax.8
14. 7 xdu    (%var_810.1 & #0xF.1), %var_598.8 ; 18000A879 u=sp+C8.1    d=sp+340.8
14. 8 mov    #0x27.4, %var_8A8.4     ; 18000A8E0 u=           d=sp+30.4
14. 9 goto   @3                      ; 18000A8E8 u=
14. 9
15. 0 ; 1WAY-BLOCK 15 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A8ED END=18000A931] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
15. 0 ; USE: ds.2,sp+D8.8,sp+134.4,(GLBLOW,sp+0..D8,sp+E0..134,sp+138..,SHADOW,ARGS,GLBHIGH)
15. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+138.4,sp+338.8
15. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
15. 0 shr    %var_800.8, #0x18.1, %var_5A0.8 ; 18000A8FC u=sp+D8.8    d=sp+338.8
15. 1 mov    &($p_InLoadOrderModuleList_1).8, rcx.8 ; 18000A908 u=           d=rcx.8
15. 2 mov    #0.1, cf.1              ; 18000A916 u=           d=cf.1
15. 3 mov    #0.1, of.1              ; 18000A916 u=           d=of.1
15. 4 setz   (%var_7A4.4 | (#0x10000000.4*xdu.4([ds.2:((%var_800.8 >>l #0x1C.1)+&($p_InLoadOrderModuleList_1).8)].1))), #0.4, zf.1 ; 18000A916 u=ds.2,sp+D8.8,sp+134.4,(GLBLOW,sp+0..D8,sp+E0..134,sp+138..,SHADOW,ARGS,GLBHIGH) d=zf.1
15. 5 setp   (%var_7A4.4 | (#0x10000000.4*xdu.4([ds.2:((%var_800.8 >>l #0x1C.1)+&($p_InLoadOrderModuleList_1).8)].1))), #0.4, pf.1 ; 18000A916 u=ds.2,sp+D8.8,sp+134.4,(GLBLOW,sp+0..D8,sp+E0..134,sp+138..,SHADOW,ARGS,GLBHIGH) d=pf.1
15. 6 sets   (%var_7A4.4 | (#0x10000000.4*xdu.4([ds.2:((%var_800.8 >>l #0x1C.1)+&($p_InLoadOrderModuleList_1).8)].1))), sf.1 ; 18000A916 u=ds.2,sp+D8.8,sp+134.4,(GLBLOW,sp+0..D8,sp+E0..134,sp+138..,SHADOW,ARGS,GLBHIGH) d=sf.1
15. 7 xdu    (%var_7A4.4 | (#0x10000000.4*xdu.4([ds.2:((%var_800.8 >>l #0x1C.1)+&($p_InLoadOrderModuleList_1).8)].1))), rax.8 ; 18000A916 u=ds.2,sp+D8.8,sp+134.4,(GLBLOW,sp+0..D8,sp+E0..134,sp+138..,SHADOW,ARGS,GLBHIGH) d=rax.8
15. 8 or     %var_7A4.4, (#0x10000000.4*xdu.4([ds.2:((%var_800.8 >>l #0x1C.1)+&($p_InLoadOrderModuleList_1).8)].1)), %var_7A0.4 ; 18000A91D u=ds.2,sp+D8.8,sp+134.4,(GLBLOW,sp+0..D8,sp+E0..134,sp+138..,SHADOW,ARGS,GLBHIGH) d=sp+138.4
15. 9 mov    #0x26.4, %var_8A8.4     ; 18000A924 u=           d=sp+30.4
15.10 goto   @3                      ; 18000A92C u=
15.10
16. 0 ; 1WAY-BLOCK 16 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A931 END=18000A965] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
16. 0 ; USE: ds.2,sp+13C.4,sp+350.1,(GLBLOW,sp+0..13C,sp+140..350,sp+351..,SHADOW,ARGS,GLBHIGH)
16. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+140.4
16. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
16. 0 mov    &($p_InLoadOrderModuleList_1).8, rcx.8 ; 18000A93C u=           d=rcx.8
16. 1 mov    #0.1, cf.1              ; 18000A94A u=           d=cf.1
16. 2 mov    #0.1, of.1              ; 18000A94A u=           d=of.1
16. 3 setz   (%var_79C.4 | (#0x100000.4*xdu.4([ds.2:(xdu.8((%var_588.1 & #0xF.1))+&($p_InLoadOrderModuleList_1).8)].1))), #0.4, zf.1 ; 18000A94A u=ds.2,sp+13C.4,sp+350.1,(GLBLOW,sp+0..13C,sp+140..350,sp+351..,SHADOW,ARGS,GLBHIGH) d=zf.1
16. 4 setp   (%var_79C.4 | (#0x100000.4*xdu.4([ds.2:(xdu.8((%var_588.1 & #0xF.1))+&($p_InLoadOrderModuleList_1).8)].1))), #0.4, pf.1 ; 18000A94A u=ds.2,sp+13C.4,sp+350.1,(GLBLOW,sp+0..13C,sp+140..350,sp+351..,SHADOW,ARGS,GLBHIGH) d=pf.1
16. 5 sets   (%var_79C.4 | (#0x100000.4*xdu.4([ds.2:(xdu.8((%var_588.1 & #0xF.1))+&($p_InLoadOrderModuleList_1).8)].1))), sf.1 ; 18000A94A u=ds.2,sp+13C.4,sp+350.1,(GLBLOW,sp+0..13C,sp+140..350,sp+351..,SHADOW,ARGS,GLBHIGH) d=sf.1
16. 6 xdu    (%var_79C.4 | (#0x100000.4*xdu.4([ds.2:(xdu.8((%var_588.1 & #0xF.1))+&($p_InLoadOrderModuleList_1).8)].1))), rax.8 ; 18000A94A u=ds.2,sp+13C.4,sp+350.1,(GLBLOW,sp+0..13C,sp+140..350,sp+351..,SHADOW,ARGS,GLBHIGH) d=rax.8
16. 7 or     %var_79C.4, (#0x100000.4*xdu.4([ds.2:(xdu.8((%var_588.1 & #0xF.1))+&($p_InLoadOrderModuleList_1).8)].1)), %var_798.4 ; 18000A951 u=ds.2,sp+13C.4,sp+350.1,(GLBLOW,sp+0..13C,sp+140..350,sp+351..,SHADOW,ARGS,GLBHIGH) d=sp+140.4
16. 8 mov    #0x29.4, %var_8A8.4     ; 18000A958 u=           d=sp+30.4
16. 9 goto   @3                      ; 18000A960 u=
16. 9
17. 0 ; 1WAY-BLOCK 17 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A965 END=18000A99A] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
17. 0 ; USE: ds.2,sp+60.4,sp+4A0.8,(GLBLOW,sp+0..60,sp+64..4A0,sp+4A8..,SHADOW,ARGS,GLBHIGH)
17. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+4A8.8
17. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
17. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000A96F u=           d=rcx.8
17. 1 or     %var_438.8, xdu.8((#0x100000.4*xdu.4([ds.2:(xdu.8(((%var_878.4 >>l #0x14.1) & #0xF.4))+&($p_InLoadOrderModuleList_5).8)].1))), rax.8 ; 18000A97D u=ds.2,sp+60.4,sp+4A0.8,(GLBLOW,sp+0..60,sp+64..4A0,sp+4A8..,SHADOW,ARGS,GLBHIGH) d=rax.8
17. 2 mov    #0.1, cf.1              ; 18000A97D u=           d=cf.1
17. 3 mov    #0.1, of.1              ; 18000A97D u=           d=of.1
17. 4 setz   (%var_438.8 | xdu.8((#0x100000.4*xdu.4([ds.2:(xdu.8(((%var_878.4 >>l #0x14.1) & #0xF.4))+&($p_InLoadOrderModuleList_5).8)].1)))), #0.8, zf.1 ; 18000A97D u=ds.2,sp+60.4,sp+4A0.8,(GLBLOW,sp+0..60,sp+64..4A0,sp+4A8..,SHADOW,ARGS,GLBHIGH) d=zf.1
17. 5 setp   (%var_438.8 | xdu.8((#0x100000.4*xdu.4([ds.2:(xdu.8(((%var_878.4 >>l #0x14.1) & #0xF.4))+&($p_InLoadOrderModuleList_5).8)].1)))), #0.8, pf.1 ; 18000A97D u=ds.2,sp+60.4,sp+4A0.8,(GLBLOW,sp+0..60,sp+64..4A0,sp+4A8..,SHADOW,ARGS,GLBHIGH) d=pf.1
17. 6 sets   (%var_438.8 | xdu.8((#0x100000.4*xdu.4([ds.2:(xdu.8(((%var_878.4 >>l #0x14.1) & #0xF.4))+&($p_InLoadOrderModuleList_5).8)].1)))), sf.1 ; 18000A97D u=ds.2,sp+60.4,sp+4A0.8,(GLBLOW,sp+0..60,sp+64..4A0,sp+4A8..,SHADOW,ARGS,GLBHIGH) d=sf.1
17. 7 or     %var_438.8, xdu.8((#0x100000.4*xdu.4([ds.2:(xdu.8(((%var_878.4 >>l #0x14.1) & #0xF.4))+&($p_InLoadOrderModuleList_5).8)].1))), %var_430.8 ; 18000A985 u=ds.2,sp+60.4,sp+4A0.8,(GLBLOW,sp+0..60,sp+64..4A0,sp+4A8..,SHADOW,ARGS,GLBHIGH) d=sp+4A8.8
17. 8 mov    #0x52.4, %var_8A8.4     ; 18000A98D u=           d=sp+30.4
17. 9 goto   @3                      ; 18000A995 u=
17. 9
18. 0 ; 1WAY-BLOCK 18 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A99A END=18000A9D6] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
18. 0 ; USE: ds.2,sp+14C.4,sp+348.1,sp+358.8,(GLBLOW,sp+0..14C,sp+150..348,sp+349..358,sp+360..,SHADOW,ARGS,GLBHIGH)
18. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+150.4,sp+360.8
18. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
18. 0 or     %var_78C.4, (#0x10.4*xdu.4([ds.2:%var_580.8].1)), %var_788.4 ; 18000A9AF u=ds.2,sp+14C.4,sp+358.8,(GLBLOW,sp+0..14C,sp+150..358,sp+360..,SHADOW,ARGS,GLBHIGH) d=sp+150.4
18. 1 mov    #0.1, cf.1              ; 18000A9BE u=           d=cf.1
18. 2 mov    #0.1, of.1              ; 18000A9BE u=           d=of.1
18. 3 setz   xdu.4((%var_590.1 & #0xF.1)), #0.4, zf.1 ; 18000A9BE u=sp+348.1   d=zf.1
18. 4 setp   xdu.4((%var_590.1 & #0xF.1)), #0.4, pf.1 ; 18000A9BE u=sp+348.1   d=pf.1
18. 5 mov    #0.1, sf.1              ; 18000A9BE u=           d=sf.1
18. 6 xdu    (%var_590.1 & #0xF.1), rax.8 ; 18000A9BE u=sp+348.1   d=rax.8
18. 7 xdu    (%var_590.1 & #0xF.1), %var_578.8 ; 18000A9C1 u=sp+348.1   d=sp+360.8
18. 8 mov    #0x2D.4, %var_8A8.4     ; 18000A9C9 u=           d=sp+30.4
18. 9 goto   @3                      ; 18000A9D1 u=
18. 9
19. 0 ; 1WAY-BLOCK 19 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000A9D6 END=18000AA85] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
19. 0 ; USE: ds.2,sp+40.4,sp+390..3A0,(GLBLOW,sp+0..40,sp+44..390,sp+3A0..,SHADOW,ARGS,GLBHIGH)
19. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+55.1,sp+3A0.8
19. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
19. 0 or     %var_540.8, %var_548.8, %var_538.8 ; 18000A9E6 u=sp+390..3A0 d=sp+3A0.8
19. 1 mov    #0.1, cf.1              ; 18000AA66 u=           d=cf.1
19. 2 mov    #0.1, of.1              ; 18000AA66 u=           d=of.1
19. 3 setz   ((%var_898.4 >>l #0x14.1) & #0xF.4), #0.4, zf.1 ; 18000AA66 u=sp+40.4    d=zf.1
19. 4 setp   ((%var_898.4 >>l #0x14.1) & #0xF.4), #0.4, pf.1 ; 18000AA66 u=sp+40.4    d=pf.1
19. 5 mov    #0.1, sf.1              ; 18000AA66 u=           d=sf.1
19. 6 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000AA69 u=           d=rcx.8
19. 7 xdu    [ds.2:(xdu.8(((%var_898.4 >>l #0x14.1) & #0xF.4))+&($p_InLoadOrderModuleList_5).8)].1, rax.8 ; 18000AA70 u=ds.2,sp+40.4,(GLBLOW,sp+0..40,sp+44..,SHADOW,ARGS,GLBHIGH) d=rax.8
19. 8 ldx    ds.2, (xdu.8(((%var_898.4 >>l #0x14.1) & #0xF.4))+&($p_InLoadOrderModuleList_5).8), %var_883.1 ; 18000AA74 u=ds.2,sp+40.4,(GLBLOW,sp+0..40,sp+44..,SHADOW,ARGS,GLBHIGH) d=sp+55.1
19. 9 mov    #0x36.4, %var_8A8.4     ; 18000AA78 u=           d=sp+30.4
19.10 goto   @3                      ; 18000AA80 u=
19.10
20. 0 ; 1WAY-BLOCK 20 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000AA85 END=18000AAF8] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
20. 0 ; USE: ds.2,sp+3B8.9,(GLBLOW,sp+0..3B8,sp+3C1..,SHADOW,ARGS,GLBHIGH)
20. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+3C8.8
20. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
20. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000AACC u=           d=rcx.8
20. 1 or     %var_520.8, (#0x100000000000000.8*xdu.8([ds.2:(xdu.8((%var_518.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)), rax.8 ; 18000AADB u=ds.2,sp+3B8.9,(GLBLOW,sp+0..3B8,sp+3C1..,SHADOW,ARGS,GLBHIGH) d=rax.8
20. 2 mov    #0.1, cf.1              ; 18000AADB u=           d=cf.1
20. 3 mov    #0.1, of.1              ; 18000AADB u=           d=of.1
20. 4 setz   (%var_520.8 | (#0x100000000000000.8*xdu.8([ds.2:(xdu.8((%var_518.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, zf.1 ; 18000AADB u=ds.2,sp+3B8.9,(GLBLOW,sp+0..3B8,sp+3C1..,SHADOW,ARGS,GLBHIGH) d=zf.1
20. 5 setp   (%var_520.8 | (#0x100000000000000.8*xdu.8([ds.2:(xdu.8((%var_518.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, pf.1 ; 18000AADB u=ds.2,sp+3B8.9,(GLBLOW,sp+0..3B8,sp+3C1..,SHADOW,ARGS,GLBHIGH) d=pf.1
20. 6 sets   (%var_520.8 | (#0x100000000000000.8*xdu.8([ds.2:(xdu.8((%var_518.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), sf.1 ; 18000AADB u=ds.2,sp+3B8.9,(GLBLOW,sp+0..3B8,sp+3C1..,SHADOW,ARGS,GLBHIGH) d=sf.1
20. 7 or     %var_520.8, (#0x100000000000000.8*xdu.8([ds.2:(xdu.8((%var_518.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)), %var_510.8 ; 18000AAE3 u=ds.2,sp+3B8.9,(GLBLOW,sp+0..3B8,sp+3C1..,SHADOW,ARGS,GLBHIGH) d=sp+3C8.8
20. 8 mov    #0x39.4, %var_8A8.4     ; 18000AAEB u=           d=sp+30.4
20. 9 goto   @3                      ; 18000AAF3 u=
20. 9
21. 0 ; 1WAY-BLOCK 21 INBOUNDS: 4 OUTBOUNDS: 22 [START=18000AAF8 END=18000AB1A] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
21. 0 ; USE: sp+458.8,(rax.8,rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..458,sp+460..,SHADOW,ARGS,GLBHIGH)
21. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rdx.8,rcx.8,r8.8,r9.8,(rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
21. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
21. 0 cfadd  %var_480.8, #0x5C.8, cf.1 ; 18000AB00 u=sp+458.8   d=cf.1
21. 1 ofadd  #0x5C.8, %var_480.8, of.1 ; 18000AB00 u=sp+458.8   d=of.1
21. 2 setz   (%var_480.8+#0x5C.8), #0.8, zf.1 ; 18000AB00 u=sp+458.8   d=zf.1
21. 3 setp   (%var_480.8+#0x5C.8), #0.8, pf.1 ; 18000AB00 u=sp+458.8   d=pf.1
21. 4 sets   (%var_480.8+#0x5C.8), sf.1 ; 18000AB00 u=sp+458.8   d=sf.1
21. 5 add    %var_480.8, #0x5C.8, rdx.8 ; 18000AB00 u=sp+458.8   d=rdx.8
21. 6 mov    #0x20.8, rcx.8          ; 18000AB04 u=           d=rcx.8
21. 7 mov    #0xE.8, r8.8            ; 18000AB09 u=           d=r8.8
21. 8 mov    #0x51.8, r9.8           ; 18000AB0F u=           d=r9.8
21. 9 call   $sub_1800E4350          ; 18000AB15 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
21. 9
22. 0 ; 2WAY-BLOCK 22 INBOUNDS: 21 OUTBOUNDS: 23 292 [START=18000AB1A END=18000AB27] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
22. 0 ; USE: eax.4,sp+15C.4
22. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1
22. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
22. 0 setb   eax.4, %var_77C.4, cf.1 ; 18000AB1A u=eax.4,sp+15C.4 d=cf.1
22. 1 seto   eax.4, %var_77C.4, of.1 ; 18000AB1A u=eax.4,sp+15C.4 d=of.1
22. 2 setz   eax.4, %var_77C.4, zf.1 ; 18000AB1A u=eax.4,sp+15C.4 d=zf.1
22. 3 setp   eax.4, %var_77C.4, pf.1 ; 18000AB1A u=eax.4,sp+15C.4 d=pf.1
22. 4 sets   (eax.4-%var_77C.4), sf.1 ; 18000AB1A u=eax.4,sp+15C.4 d=sf.1
22. 5 jnz    eax.4, %var_77C.4, @292 ; 18000AB21 u=eax.4,sp+15C.4
22. 5
23. 0 ; 1WAY-BLOCK 23 INBOUNDS: 22 OUTBOUNDS: 3 [START=18000AB27 END=18000AB34] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
23. 0 ; DEF: sp+30.4
23. 0 mov    #0x49.4, %var_8A8.4     ; 18000AB27 u=           d=sp+30.4
23. 1 goto   @3                      ; 18000AB2F u=
23. 1
24. 0 ; 1WAY-BLOCK 24 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000AB34 END=18000ABAC] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
24. 0 ; USE: sp+5C0.8
24. 0 ; DEF: cf.1,of.1,rax.8,sp+30.4,sp+5C8.8
24. 0 ; DNU: cf.1,of.1
24. 0 mov    call !__ROL8__<fast:_QWORD %var_318.8,char #0x1F.1>.8, rax.8 ; 18000AB93 u=sp+5C0.8   d=rax.8
24. 1 cfshl  %var_318.8, #0x1F.1, cf.1 ; 18000AB93 u=sp+5C0.8   d=cf.1
24. 2 und    of.1                    ; 18000AB93 u=           d=of.1
24. 3 mov    rax.8, %var_310.8       ; 18000AB97 u=rax.8      d=sp+5C8.8
24. 4 mov    #0x75.4, %var_8A8.4     ; 18000AB9F u=           d=sp+30.4
24. 5 goto   @3                      ; 18000ABA7 u=
24. 5
25. 0 ; 1WAY-BLOCK 25 INBOUNDS: 4 OUTBOUNDS: 26 [START=18000ABAC END=18000ABD9] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
25. 0 ; USE: rsp.8,sp+5E8.8,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..5E8,sp+5F0..,SHADOW,ARGS,GLBHIGH)
25. 0 ; DEF: rax.16,rcx.8,r8.8,r9.8,sp+290.8,(cf.1,zf.1,sf.1,of.1,pf.1,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..290,sp+298..,RET,SHADOW,ARGS,GLBHIGH)
25. 0 mov    %var_2F0.8, rax.8       ; 18000ABAC u=sp+5E8.8   d=rax.8
25. 1 mov    %var_2F0.8, %var_648.8  ; 18000ABB4 u=sp+5E8.8   d=sp+290.8
25. 2 add    rsp.8, #0x290.8, r8.8   ; 18000ABBC u=rsp.8      d=r8.8
25. 3 mov    #0x22.8, rcx.8          ; 18000ABC4 u=           d=rcx.8
25. 4 mov    #0x32.8, rdx.8          ; 18000ABC9 u=           d=rdx.8
25. 5 mov    #0x63.8, r9.8           ; 18000ABCE u=           d=r9.8
25. 6 call   $sub_1800E3F00          ; 18000ABD4 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
25. 6
26. 0 ; 1WAY-BLOCK 26 INBOUNDS: 25 OUTBOUNDS: 3 [START=18000ABD9 END=18000ABFA] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
26. 0 ; USE: sp+290.8
26. 0 ; DEF: cf.1,of.1,rax.8,sp+30.4,sp+5F0.8
26. 0 ; DNU: cf.1,of.1
26. 0 mov    call !__ROL8__<fast:_QWORD %var_648.8,char #7.1>.8, rax.8 ; 18000ABE1 u=sp+290.8   d=rax.8
26. 1 cfshl  %var_648.8, #7.1, cf.1  ; 18000ABE1 u=sp+290.8   d=cf.1
26. 2 und    of.1                    ; 18000ABE1 u=           d=of.1
26. 3 mov    rax.8, %var_2E8.8       ; 18000ABE5 u=rax.8      d=sp+5F0.8
26. 4 mov    #0x7D.4, %var_8A8.4     ; 18000ABED u=           d=sp+30.4
26. 5 goto   @3                      ; 18000ABF5 u=
26. 5
27. 0 ; 1WAY-BLOCK 27 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000ABFA END=18000AC2E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
27. 0 ; USE: ds.2,sp+428..438,(GLBLOW,sp+0..428,sp+438..,SHADOW,ARGS,GLBHIGH)
27. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+438.8
27. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
27. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000AC02 u=           d=rcx.8
27. 1 or     %var_4B0.8, (#0x10000000000.8*xdu.8([ds.2:(%var_4A8.8+&($p_InLoadOrderModuleList_5).8)].1)), rax.8 ; 18000AC11 u=ds.2,sp+428..438,(GLBLOW,sp+0..428,sp+438..,SHADOW,ARGS,GLBHIGH) d=rax.8
27. 2 mov    #0.1, cf.1              ; 18000AC11 u=           d=cf.1
27. 3 mov    #0.1, of.1              ; 18000AC11 u=           d=of.1
27. 4 setz   (%var_4B0.8 | (#0x10000000000.8*xdu.8([ds.2:(%var_4A8.8+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, zf.1 ; 18000AC11 u=ds.2,sp+428..438,(GLBLOW,sp+0..428,sp+438..,SHADOW,ARGS,GLBHIGH) d=zf.1
27. 5 setp   (%var_4B0.8 | (#0x10000000000.8*xdu.8([ds.2:(%var_4A8.8+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, pf.1 ; 18000AC11 u=ds.2,sp+428..438,(GLBLOW,sp+0..428,sp+438..,SHADOW,ARGS,GLBHIGH) d=pf.1
27. 6 sets   (%var_4B0.8 | (#0x10000000000.8*xdu.8([ds.2:(%var_4A8.8+&($p_InLoadOrderModuleList_5).8)].1))), sf.1 ; 18000AC11 u=ds.2,sp+428..438,(GLBLOW,sp+0..428,sp+438..,SHADOW,ARGS,GLBHIGH) d=sf.1
27. 7 or     %var_4B0.8, (#0x10000000000.8*xdu.8([ds.2:(%var_4A8.8+&($p_InLoadOrderModuleList_5).8)].1)), %var_4A0.8 ; 18000AC19 u=ds.2,sp+428..438,(GLBLOW,sp+0..428,sp+438..,SHADOW,ARGS,GLBHIGH) d=sp+438.8
27. 8 mov    #0x43.4, %var_8A8.4     ; 18000AC21 u=           d=sp+30.4
27. 9 goto   @3                      ; 18000AC29 u=
27. 9
28. 0 ; 1WAY-BLOCK 28 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000AC2E END=18000ACB6] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
28. 0 ; USE: ds.2,sp+60.8,sp+508..518,(GLBLOW,sp+0..60,sp+68..508,sp+518..,SHADOW,ARGS,GLBHIGH)
28. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+518..528
28. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
28. 0 or     %var_3D0.8, (#0x1000000000000.8*xdu.8([ds.2:%var_3C8.8].1)), %var_3C0.8 ; 18000AC90 u=ds.2,sp+508..518,(GLBLOW,sp+0..508,sp+518..,SHADOW,ARGS,GLBHIGH) d=sp+518.8
28. 1 cfshr  %var_878.8, #0x28.1, cf.1 ; 18000AC9D u=sp+60.8    d=cf.1
28. 2 shr    %var_878.8, #0x28.1, rax.8 ; 18000AC9D u=sp+60.8    d=rax.8
28. 3 und    of.1                    ; 18000AC9D u=           d=of.1
28. 4 setz   (%var_878.8 >>l #0x28.1), #0.8, zf.1 ; 18000AC9D u=sp+60.8    d=zf.1
28. 5 setp   (%var_878.8 >>l #0x28.1), #0.8, pf.1 ; 18000AC9D u=sp+60.8    d=pf.1
28. 6 mov    #0.1, sf.1              ; 18000AC9D u=           d=sf.1
28. 7 shr    %var_878.8, #0x28.1, %var_3B8.8 ; 18000ACA1 u=sp+60.8    d=sp+520.8
28. 8 mov    #0x5B.4, %var_8A8.4     ; 18000ACA9 u=           d=sp+30.4
28. 9 goto   @3                      ; 18000ACB1 u=
28. 9
29. 0 ; 1WAY-BLOCK 29 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000ACB6 END=18000AD29] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
29. 0 ; USE: sp+5B8.8
29. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+5C0.8
29. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
29. 0 setz   (%var_320.8 ^ #0x3DB71325EC41CAD9.8), #0.8, zf.1 ; 18000ACC0 u=sp+5B8.8   d=zf.1
29. 1 setp   (%var_320.8 ^ #0x3DB71325EC41CAD9.8), #0.8, pf.1 ; 18000ACC0 u=sp+5B8.8   d=pf.1
29. 2 sets   %var_320.8, sf.1        ; 18000ACC0 u=sp+5B8.8   d=sf.1
29. 3 mov    call !__ROL8__<fast:_QWORD (%var_320.8 ^ #0x3DB71325EC41CAD9.8),char #0x21.1>.8, rax.8 ; 18000ACC8 u=sp+5B8.8   d=rax.8
29. 4 cfshl  (%var_320.8 ^ #0x3DB71325EC41CAD9.8), #0x21.1, cf.1 ; 18000ACC8 u=sp+5B8.8   d=cf.1
29. 5 und    of.1                    ; 18000ACC8 u=           d=of.1
29. 6 mov    rax.8, %var_318.8       ; 18000ACCC u=rax.8      d=sp+5C0.8
29. 7 mov    #0x74.4, %var_8A8.4     ; 18000AD1C u=           d=sp+30.4
29. 8 goto   @3                      ; 18000AD24 u=
29. 8
30. 0 ; 1WAY-BLOCK 30 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000AD29 END=18000AD47] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
30. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+48.2
30. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
30. 0 mov    #0xAB.1, %var_890.1     ; 18000AD29 u=           d=sp+48.1
30. 1 mov    #0xAB.8, rax.8          ; 18000AD2E u=           d=rax.8
30. 2 mov    #1.1, cf.1              ; 18000AD33 u=           d=cf.1
30. 3 mov    #0.1, of.1              ; 18000AD33 u=           d=of.1
30. 4 mov    #0.1, zf.1              ; 18000AD33 u=           d=zf.1
30. 5 setp   #0xF8.1, #0.1, pf.1     ; 18000AD33 u=           d=pf.1
30. 6 mov    #1.1, sf.1              ; 18000AD33 u=           d=sf.1
30. 7 mov    #0.1, %var_88F.1        ; 18000AD35 u=           d=sp+49.1
30. 8 mov    #2.4, %var_8A8.4        ; 18000AD3A u=           d=sp+30.4
30. 9 goto   @3                      ; 18000AD42 u=
30. 9
31. 0 ; 1WAY-BLOCK 31 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000AD47 END=18000ADB9] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
31. 0 ; USE: sp+C4.4
31. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+78.8,sp+110.4
31. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
31. 0 cfadd  (%var_814.4 ^ #0xA70B480C.4), #0x8E232396.4, cf.1 ; 18000AD53 u=sp+C4.4    d=cf.1
31. 1 ofadd  #0x8E232396.4, (%var_814.4 ^ #0xA70B480C.4), of.1 ; 18000AD53 u=sp+C4.4    d=of.1
31. 2 setz   (%var_814.4 ^ #0xA70B480C.4), #0x71DCDC6A.4, zf.1 ; 18000AD53 u=sp+C4.4    d=zf.1
31. 3 setp   (%var_814.4 ^ #0xA70B480C.4), #0x71DCDC6A.4, pf.1 ; 18000AD53 u=sp+C4.4    d=pf.1
31. 4 sets   ((%var_814.4 ^ #0xA70B480C.4)-#0x71DCDC6A.4), sf.1 ; 18000AD53 u=sp+C4.4    d=sf.1
31. 5 xdu    ((%var_814.4 ^ #0xA70B480C.4)-#0x71DCDC6A.4), rax.8 ; 18000AD53 u=sp+C4.4    d=rax.8
31. 6 sub    (%var_814.4 ^ #0xA70B480C.4), #0x71DCDC6A.4, %var_7C8.4 ; 18000AD58 u=sp+C4.4    d=sp+110.4
31. 7 xdu    ((%var_814.4 ^ #0xA70B480C.4)-#0x71DCDC6A.4), %var_860.8 ; 18000AD5F u=sp+C4.4    d=sp+78.8
31. 8 mov    #0x18.4, %var_8A8.4     ; 18000ADAC u=           d=sp+30.4
31. 9 goto   @3                      ; 18000ADB4 u=
31. 9
32. 0 ; 1WAY-BLOCK 32 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000ADB9 END=18000AE3F] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
32. 0 ; USE: ds.2,sp+40.8,(GLBLOW,sp+0..40,sp+48..,SHADOW,ARGS,GLBHIGH)
32. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+57.1,sp+410.8
32. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
32. 0 shr    %var_898.8, #0x28.1, %var_4C8.8 ; 18000ADC2 u=sp+40.8    d=sp+410.8
32. 1 mov    #0.1, cf.1              ; 18000AE20 u=           d=cf.1
32. 2 mov    #0.1, of.1              ; 18000AE20 u=           d=of.1
32. 3 setz   (low.4((%var_898.8 >>l #0x2C.1)) & #0xF.4), #0.4, zf.1 ; 18000AE20 u=sp+40.8    d=zf.1
32. 4 setp   (low.4((%var_898.8 >>l #0x2C.1)) & #0xF.4), #0.4, pf.1 ; 18000AE20 u=sp+40.8    d=pf.1
32. 5 mov    #0.1, sf.1              ; 18000AE20 u=           d=sf.1
32. 6 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000AE23 u=           d=rcx.8
32. 7 xdu    [ds.2:(((%var_898.8 >>l #0x2C.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1, rax.8 ; 18000AE2A u=ds.2,sp+40.8,(GLBLOW,sp+0..40,sp+48..,SHADOW,ARGS,GLBHIGH) d=rax.8
32. 8 ldx    ds.2, (((%var_898.8 >>l #0x2C.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8), %var_881.1 ; 18000AE2E u=ds.2,sp+40.8,(GLBLOW,sp+0..40,sp+48..,SHADOW,ARGS,GLBHIGH) d=sp+57.1
32. 9 mov    #0x40.4, %var_8A8.4     ; 18000AE32 u=           d=sp+30.4
32.10 goto   @3                      ; 18000AE3A u=
32.10
33. 0 ; 1WAY-BLOCK 33 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000AE3F END=18000AE82] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
33. 0 ; USE: sp+110.1,sp+114.8
33. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+52.1,sp+11C.4,sp+310.8
33. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
33. 0 or     %var_7C4.4, %var_7C0.4, %var_7BC.4 ; 18000AE4D u=sp+114.8   d=sp+11C.4
33. 1 mov    %var_7C8.1, %var_886.1  ; 18000AE5C u=sp+110.1   d=sp+52.1
33. 2 xdu    (%var_7C8.1 & #0xF.1), rax.8 ; 18000AE60 u=sp+110.1   d=rax.8
33. 3 cfadd  rax.8, &($p_InLoadOrderModuleList_10).8, cf.1 ; 18000AE6A u=rax.8      d=cf.1
33. 4 ofadd  rax.8, &($p_InLoadOrderModuleList_10).8, of.1 ; 18000AE6A u=rax.8      d=of.1
33. 5 setz   (rax.8+&($p_InLoadOrderModuleList_10).8), #0.8, zf.1 ; 18000AE6A u=rax.8      d=zf.1
33. 6 setp   (rax.8+&($p_InLoadOrderModuleList_10).8), #0.8, pf.1 ; 18000AE6A u=rax.8      d=pf.1
33. 7 sets   (rax.8+&($p_InLoadOrderModuleList_10).8), sf.1 ; 18000AE6A u=rax.8      d=sf.1
33. 8 add    rax.8, &($p_InLoadOrderModuleList_10).8, rcx.8 ; 18000AE6A u=rax.8      d=rcx.8
33. 9 add    rax.8, &($p_InLoadOrderModuleList_10).8, %var_5C8.8 ; 18000AE6D u=rax.8      d=sp+310.8
33.10 mov    #0x1B.4, %var_8A8.4     ; 18000AE75 u=           d=sp+30.4
33.11 goto   @3                      ; 18000AE7D u=
33.11
34. 0 ; 1WAY-BLOCK 34 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000AE82 END=18000AEF9] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
34. 0 ; USE: ds.2,sp+40.8,sp+440.8,(GLBLOW,sp+0..40,sp+48..440,sp+448..,SHADOW,ARGS,GLBHIGH)
34. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+448.8
34. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
34. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000AE8B u=           d=rcx.8
34. 1 or     %var_498.8, (#0x1000000000000000.8*xdu.8([ds.2:((%var_898.8 >>l #0x3C.1)+&($p_InLoadOrderModuleList_5).8)].1)), rax.8 ; 18000AE9A u=ds.2,sp+40.8,sp+440.8,(GLBLOW,sp+0..40,sp+48..440,sp+448..,SHADOW,ARGS,GLBHIGH) d=rax.8
34. 2 setz   (%var_498.8 | (#0x1000000000000000.8*xdu.8([ds.2:((%var_898.8 >>l #0x3C.1)+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, zf.1 ; 18000AE9A u=ds.2,sp+40.8,sp+440.8,(GLBLOW,sp+0..40,sp+48..440,sp+448..,SHADOW,ARGS,GLBHIGH) d=zf.1
34. 3 setp   (%var_498.8 | (#0x1000000000000000.8*xdu.8([ds.2:((%var_898.8 >>l #0x3C.1)+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, pf.1 ; 18000AE9A u=ds.2,sp+40.8,sp+440.8,(GLBLOW,sp+0..40,sp+48..440,sp+448..,SHADOW,ARGS,GLBHIGH) d=pf.1
34. 4 sets   (%var_498.8 | (#0x1000000000000000.8*xdu.8([ds.2:((%var_898.8 >>l #0x3C.1)+&($p_InLoadOrderModuleList_5).8)].1))), sf.1 ; 18000AE9A u=ds.2,sp+40.8,sp+440.8,(GLBLOW,sp+0..40,sp+48..440,sp+448..,SHADOW,ARGS,GLBHIGH) d=sf.1
34. 5 cfshl  rax.8, #0x3D.1, tt.1    ; 18000AEA2 u=rax.8      d=tt.1
34. 6 mov    call !__ROL8__<fast:_QWORD rax.8,char #0x3D.1>.8, rax.8 ; 18000AEA2 u=rax.8      d=rax.8
34. 7 mov    tt.1, cf.1              ; 18000AEA2 u=tt.1       d=cf.1
34. 8 und    of.1                    ; 18000AEA2 u=           d=of.1
34. 9 mov    rax.8, %var_490.8       ; 18000AEA6 u=rax.8      d=sp+448.8
34.10 mov    #0x45.4, %var_8A8.4     ; 18000AEEC u=           d=sp+30.4
34.11 goto   @3                      ; 18000AEF4 u=
34.11
35. 0 ; 1WAY-BLOCK 35 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000AEF9 END=18000AFA9] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
35. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+2E8.8,sp+570.8
35. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
35. 0 mov    #-0x33758B660E867CB.8, %var_5F0.8 ; 18000AF03 u=           d=sp+2E8.8
35. 1 mov    #-0x33758B660E867CB.8, rax.8 ; 18000AF0B u=           d=rax.8
35. 2 mov    #1.1, cf.1              ; 18000AF91 u=           d=cf.1
35. 3 ofadd  #-0x33758B660E867CB.8, #-0x3CAAF69DD581F67A.8, of.1 ; 18000AF91 u=           d=of.1
35. 4 mov    #0.1, zf.1              ; 18000AF91 u=           d=zf.1
35. 5 setp   #-0x33758B660E867CB.8, #0x3CAAF69DD581F67A.8, pf.1 ; 18000AF91 u=           d=pf.1
35. 6 mov    #1.1, sf.1              ; 18000AF91 u=           d=sf.1
35. 7 mov    #-0x3FE24F54366A5E45.8, rcx.8 ; 18000AF91 u=           d=rcx.8
35. 8 mov    #-0x3FE24F54366A5E45.8, %var_368.8 ; 18000AF94 u=           d=sp+570.8
35. 9 mov    #0x63.4, %var_8A8.4     ; 18000AF9C u=           d=sp+30.4
35.10 goto   @3                      ; 18000AFA4 u=
35.10
36. 0 ; 1WAY-BLOCK 36 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000AFA9 END=18000AFB6] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
36. 0 ; DEF: sp+30.4
36. 0 mov    #0x65.4, %var_8A8.4     ; 18000AFA9 u=           d=sp+30.4
36. 1 goto   @3                      ; 18000AFB1 u=
36. 1
37. 0 ; 1WAY-BLOCK 37 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000AFB6 END=18000B035] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
37. 0 ; USE: sp+180.4,(sp+80.4)
37. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+80.8,sp+184.4,sp+630.8
37. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
37. 0 xor    %var_758.4, #0x58687F7.4, %var_754.4 ; 18000AFC2 u=sp+180.4   d=sp+184.4
37. 1 xdu    (%var_758.4 ^ #0x58687F7.4), %var_858.8 ; 18000AFC9 u=sp+180.4   d=sp+80.8
37. 2 cfshr  %var_858.4, #0x18.1, cf.1 ; 18000AFD1 u=sp+80.4    d=cf.1
37. 3 und    of.1                    ; 18000AFD1 u=           d=of.1
37. 4 setz   (%var_858.4 >>l #0x18.1), #0.4, zf.1 ; 18000AFD1 u=sp+80.4    d=zf.1
37. 5 setp   (%var_858.4 >>l #0x18.1), #0.4, pf.1 ; 18000AFD1 u=sp+80.4    d=pf.1
37. 6 mov    #0.1, sf.1              ; 18000AFD1 u=           d=sf.1
37. 7 xdu    (%var_858.4 >>l #0x18.1), rax.8 ; 18000AFD1 u=sp+80.4    d=rax.8
37. 8 xdu    (%var_858.4 >>l #0x18.1), %var_2A8.8 ; 18000AFD4 u=sp+80.4    d=sp+630.8
37. 9 mov    #0x8A.4, %var_8A8.4     ; 18000B028 u=           d=sp+30.4
37.10 goto   @3                      ; 18000B030 u=
37.10
38. 0 ; 1WAY-BLOCK 38 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B035 END=18000B117] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
38. 0 ; DEF: sp+30.4
38. 0 mov    #0x6E.4, %var_8A8.4     ; 18000B10A u=           d=sp+30.4
38. 1 goto   @3                      ; 18000B112 u=
38. 1
39. 0 ; 1WAY-BLOCK 39 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B117 END=18000B14C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
39. 0 ; USE: ds.2,sp+40.1,sp+3F8.8,(GLBLOW,sp+0..40,sp+41..3F8,sp+400..,SHADOW,ARGS,GLBHIGH)
39. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+400.8
39. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
39. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000B121 u=           d=rcx.8
39. 1 or     %var_4E0.8, xdu.8((#0x10.4*xdu.4([ds.2:(xdu.8((%var_898.1 >>l #4.1))+&($p_InLoadOrderModuleList_5).8)].1))), rax.8 ; 18000B12F u=ds.2,sp+40.1,sp+3F8.8,(GLBLOW,sp+0..40,sp+41..3F8,sp+400..,SHADOW,ARGS,GLBHIGH) d=rax.8
39. 2 mov    #0.1, cf.1              ; 18000B12F u=           d=cf.1
39. 3 mov    #0.1, of.1              ; 18000B12F u=           d=of.1
39. 4 setz   (%var_4E0.8 | xdu.8((#0x10.4*xdu.4([ds.2:(xdu.8((%var_898.1 >>l #4.1))+&($p_InLoadOrderModuleList_5).8)].1)))), #0.8, zf.1 ; 18000B12F u=ds.2,sp+40.1,sp+3F8.8,(GLBLOW,sp+0..40,sp+41..3F8,sp+400..,SHADOW,ARGS,GLBHIGH) d=zf.1
39. 5 setp   (%var_4E0.8 | xdu.8((#0x10.4*xdu.4([ds.2:(xdu.8((%var_898.1 >>l #4.1))+&($p_InLoadOrderModuleList_5).8)].1)))), #0.8, pf.1 ; 18000B12F u=ds.2,sp+40.1,sp+3F8.8,(GLBLOW,sp+0..40,sp+41..3F8,sp+400..,SHADOW,ARGS,GLBHIGH) d=pf.1
39. 6 sets   (%var_4E0.8 | xdu.8((#0x10.4*xdu.4([ds.2:(xdu.8((%var_898.1 >>l #4.1))+&($p_InLoadOrderModuleList_5).8)].1)))), sf.1 ; 18000B12F u=ds.2,sp+40.1,sp+3F8.8,(GLBLOW,sp+0..40,sp+41..3F8,sp+400..,SHADOW,ARGS,GLBHIGH) d=sf.1
39. 7 or     %var_4E0.8, xdu.8((#0x10.4*xdu.4([ds.2:(xdu.8((%var_898.1 >>l #4.1))+&($p_InLoadOrderModuleList_5).8)].1))), %var_4D8.8 ; 18000B137 u=ds.2,sp+40.1,sp+3F8.8,(GLBLOW,sp+0..40,sp+41..3F8,sp+400..,SHADOW,ARGS,GLBHIGH) d=sp+400.8
39. 8 mov    #0x3E.4, %var_8A8.4     ; 18000B13F u=           d=sp+30.4
39. 9 goto   @3                      ; 18000B147 u=
39. 9
40. 0 ; 1WAY-BLOCK 40 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B14C END=18000B185] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
40. 0 ; USE: rbx.8,sp+5F0.8
40. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+E8.4,sp+174.4,sp+5F8.8
40. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
40. 0 cfadd  rbx.8, %var_2E8.8, cf.1 ; 18000B154 u=rbx.8,sp+5F0.8 d=cf.1
40. 1 ofadd  rbx.8, %var_2E8.8, of.1 ; 18000B154 u=rbx.8,sp+5F0.8 d=of.1
40. 2 setz   (rbx.8+%var_2E8.8), #0.8, zf.1 ; 18000B154 u=rbx.8,sp+5F0.8 d=zf.1
40. 3 setp   (rbx.8+%var_2E8.8), #0.8, pf.1 ; 18000B154 u=rbx.8,sp+5F0.8 d=pf.1
40. 4 sets   (rbx.8+%var_2E8.8), sf.1 ; 18000B154 u=rbx.8,sp+5F0.8 d=sf.1
40. 5 add    rbx.8, %var_2E8.8, %var_2E0.8 ; 18000B157 u=rbx.8,sp+5F0.8 d=sp+5F8.8
40. 6 mov    #0x9F69A3D5.4, %var_7F0.4 ; 18000B15F u=           d=sp+E8.4
40. 7 mov    #0x9F69A3D5.8, rax.8    ; 18000B16A u=           d=rax.8
40. 8 mov    #0x9F69A3D5.4, %var_764.4 ; 18000B171 u=           d=sp+174.4
40. 9 mov    #0x7E.4, %var_8A8.4     ; 18000B178 u=           d=sp+30.4
40.10 goto   @3                      ; 18000B180 u=
40.10
41. 0 ; 1WAY-BLOCK 41 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B185 END=18000B21C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
41. 0 ; USE: sp+60.8,sp+470.8
41. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+478..490
41. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
41. 0 mul    #0x10000000000000.8, %var_468.8, %var_460.8 ; 18000B191 u=sp+470.8   d=sp+478.8
41. 1 shr    %var_878.8, #0x18.1, %var_458.8 ; 18000B1A2 u=sp+60.8    d=sp+480.8
41. 2 xdu    (%var_878.4 >>l #0x1C.1), rax.8 ; 18000B1AE u=sp+60.4    d=rax.8
41. 3 cfadd  rax.8, &($p_InLoadOrderModuleList_5).8, cf.1 ; 18000B204 u=rax.8      d=cf.1
41. 4 ofadd  rax.8, &($p_InLoadOrderModuleList_5).8, of.1 ; 18000B204 u=rax.8      d=of.1
41. 5 setz   (rax.8+&($p_InLoadOrderModuleList_5).8), #0.8, zf.1 ; 18000B204 u=rax.8      d=zf.1
41. 6 setp   (rax.8+&($p_InLoadOrderModuleList_5).8), #0.8, pf.1 ; 18000B204 u=rax.8      d=pf.1
41. 7 sets   (rax.8+&($p_InLoadOrderModuleList_5).8), sf.1 ; 18000B204 u=rax.8      d=sf.1
41. 8 add    rax.8, &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000B204 u=rax.8      d=rcx.8
41. 9 add    rax.8, &($p_InLoadOrderModuleList_5).8, %var_450.8 ; 18000B207 u=rax.8      d=sp+488.8
41.10 mov    #0x4F.4, %var_8A8.4     ; 18000B20F u=           d=sp+30.4
41.11 goto   @3                      ; 18000B217 u=
41.11
42. 0 ; 1WAY-BLOCK 42 INBOUNDS: 4 OUTBOUNDS: 43 [START=18000B21C END=18000B2A5] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
42. 0 ; USE: rsp.8,sp+1E0.4,sp+568.8,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..1E0,sp+1E4..568,sp+570..,SHADOW,ARGS,GLBHIGH)
42. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,sp+B8.4,sp+678.8,(r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..B8,sp+BC..678,sp+680..,RET,SHADOW,ARGS,GLBHIGH)
42. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
42. 0 mov    %var_370.8, %var_260.8  ; 18000B26D u=sp+568.8   d=sp+678.8
42. 1 mov    #0.1, cf.1              ; 18000B27A u=           d=cf.1
42. 2 mov    #0.1, of.1              ; 18000B27A u=           d=of.1
42. 3 setz   (%var_6F8.4 ^ #0xDA41153F.4), #0.4, zf.1 ; 18000B27A u=sp+1E0.4   d=zf.1
42. 4 setp   (%var_6F8.4 ^ #0xDA41153F.4), #0.4, pf.1 ; 18000B27A u=sp+1E0.4   d=pf.1
42. 5 sets   bnot(%var_6F8.4), sf.1  ; 18000B27A u=sp+1E0.4   d=sf.1
42. 6 xdu    (%var_6F8.4 ^ #0xDA41153F.4), rax.8 ; 18000B27A u=sp+1E0.4   d=rax.8
42. 7 xor    %var_6F8.4, #0xDA41153F.4, %var_820.4 ; 18000B281 u=sp+1E0.4   d=sp+B8.4
42. 8 add    rsp.8, #0xB8.8, r9.8    ; 18000B288 u=rsp.8      d=r9.8
42. 9 mov    #0x3D.8, rcx.8          ; 18000B290 u=           d=rcx.8
42.10 mov    #0x29.8, rdx.8          ; 18000B295 u=           d=rdx.8
42.11 mov    #0x34.8, r8.8           ; 18000B29A u=           d=r8.8
42.12 call   $sub_1800C24E0          ; 18000B2A0 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
42.12
43. 0 ; 1WAY-BLOCK 43 INBOUNDS: 42 OUTBOUNDS: 3 [START=18000B2A5 END=18000B2B2] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
43. 0 ; DEF: sp+30.4
43. 0 mov    #0xA4.4, %var_8A8.4     ; 18000B2A5 u=           d=sp+30.4
43. 1 goto   @3                      ; 18000B2AD u=
43. 1
44. 0 ; 1WAY-BLOCK 44 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B2B2 END=18000B2F5] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
44. 0 ; USE: sp+57.1,sp+3D0.1,sp+408.8
44. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+418..428
44. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
44. 0 or     %var_4D0.8, (#0x100000000000.8*xdu.8(%var_881.1)), %var_4C0.8 ; 18000B2C3 u=sp+57.1,sp+408.8 d=sp+418.8
44. 1 xdu    (%var_508.1 & #0xF.1), rax.8 ; 18000B2D3 u=sp+3D0.1   d=rax.8
44. 2 cfadd  rax.8, &($p_InLoadOrderModuleList_5).8, cf.1 ; 18000B2DD u=rax.8      d=cf.1
44. 3 ofadd  rax.8, &($p_InLoadOrderModuleList_5).8, of.1 ; 18000B2DD u=rax.8      d=of.1
44. 4 setz   (rax.8+&($p_InLoadOrderModuleList_5).8), #0.8, zf.1 ; 18000B2DD u=rax.8      d=zf.1
44. 5 setp   (rax.8+&($p_InLoadOrderModuleList_5).8), #0.8, pf.1 ; 18000B2DD u=rax.8      d=pf.1
44. 6 sets   (rax.8+&($p_InLoadOrderModuleList_5).8), sf.1 ; 18000B2DD u=rax.8      d=sf.1
44. 7 add    rax.8, &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000B2DD u=rax.8      d=rcx.8
44. 8 add    rax.8, &($p_InLoadOrderModuleList_5).8, %var_4B8.8 ; 18000B2E0 u=rax.8      d=sp+420.8
44. 9 mov    #0x41.4, %var_8A8.4     ; 18000B2E8 u=           d=sp+30.4
44.10 goto   @3                      ; 18000B2F0 u=
44.10
45. 0 ; 1WAY-BLOCK 45 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B2F5 END=18000B37E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
45. 0 ; USE: ds.2,sp+480.1,(GLBLOW,sp+0..480,sp+481..,SHADOW,ARGS,GLBHIGH)
45. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+4F0.8
45. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
45. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000B35B u=           d=rcx.8
45. 1 xdu    [ds.2:(xdu.8((%var_458.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1, eax.4 ; 18000B362 u=ds.2,sp+480.1,(GLBLOW,sp+0..480,sp+481..,SHADOW,ARGS,GLBHIGH) d=eax.4
45. 2 cfshl  eax.4, #0x18.1, cf.1    ; 18000B366 u=eax.4      d=cf.1
45. 3 mul    #0x1000000.4, eax.4, eax.4 ; 18000B366 u=eax.4      d=eax.4
45. 4 und    of.1                    ; 18000B366 u=           d=of.1
45. 5 setz   eax.4, #0.4, zf.1       ; 18000B366 u=eax.4      d=zf.1
45. 6 setp   eax.4, #0.4, pf.1       ; 18000B366 u=eax.4      d=pf.1
45. 7 sets   eax.4, sf.1             ; 18000B366 u=eax.4      d=sf.1
45. 8 xdu    eax.4, rax.8            ; 18000B366 u=eax.4      d=rax^4.4
45. 9 xdu    eax.4, %var_3E8.8       ; 18000B369 u=eax.4      d=sp+4F0.8
45.10 mov    #0x58.4, %var_8A8.4     ; 18000B371 u=           d=sp+30.4
45.11 goto   @3                      ; 18000B379 u=
45.11
46. 0 ; 1WAY-BLOCK 46 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B37E END=18000B3F6] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
46. 0 ; USE: ds.2,sp+630.1,(GLBLOW,sp+0..630,sp+631..,SHADOW,ARGS,GLBHIGH)
46. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+188.4
46. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
46. 0 mov    &($p_InLoadOrderModuleList_6).8, rcx.8 ; 18000B3D4 u=           d=rcx.8
46. 1 xdu    [ds.2:(xdu.8((%var_2A8.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1, eax.4 ; 18000B3DB u=ds.2,sp+630.1,(GLBLOW,sp+0..630,sp+631..,SHADOW,ARGS,GLBHIGH) d=eax.4
46. 2 cfshl  eax.4, #0x18.1, cf.1    ; 18000B3DF u=eax.4      d=cf.1
46. 3 mul    #0x1000000.4, eax.4, eax.4 ; 18000B3DF u=eax.4      d=eax.4
46. 4 und    of.1                    ; 18000B3DF u=           d=of.1
46. 5 setz   eax.4, #0.4, zf.1       ; 18000B3DF u=eax.4      d=zf.1
46. 6 setp   eax.4, #0.4, pf.1       ; 18000B3DF u=eax.4      d=pf.1
46. 7 sets   eax.4, sf.1             ; 18000B3DF u=eax.4      d=sf.1
46. 8 xdu    eax.4, rax.8            ; 18000B3DF u=eax.4      d=rax^4.4
46. 9 mov    eax.4, %var_750.4       ; 18000B3E2 u=eax.4      d=sp+188.4
46.10 mov    #0x8B.4, %var_8A8.4     ; 18000B3E9 u=           d=sp+30.4
46.11 goto   @3                      ; 18000B3F1 u=
46.11
47. 0 ; 1WAY-BLOCK 47 INBOUNDS: 4 OUTBOUNDS: 48 [START=18000B3F6 END=18000B424] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
47. 0 ; USE: rsp.8,sp+2C0.8,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..2C0,sp+2C8..,SHADOW,ARGS,GLBHIGH)
47. 0 ; DEF: rax.16,rcx.8,r8.8,r9.8,sp+278.8,(cf.1,zf.1,sf.1,of.1,pf.1,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..278,sp+280..,RET,SHADOW,ARGS,GLBHIGH)
47. 0 mov    %var_618.8, rax.8       ; 18000B3F6 u=sp+2C0.8   d=rax.8
47. 1 mov    %var_618.8, %var_660.8  ; 18000B3FE u=sp+2C0.8   d=sp+278.8
47. 2 add    rsp.8, #0x278.8, rdx.8  ; 18000B406 u=rsp.8      d=rdx.8
47. 3 mov    #0x33.8, rcx.8          ; 18000B40E u=           d=rcx.8
47. 4 mov    #7.8, r8.8              ; 18000B413 u=           d=r8.8
47. 5 mov    #0x50.8, r9.8           ; 18000B419 u=           d=r9.8
47. 6 call   $sub_1801BCFF0          ; 18000B41F u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
47. 6
48. 0 ; 1WAY-BLOCK 48 INBOUNDS: 47 OUTBOUNDS: 3 [START=18000B424 END=18000B451] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
48. 0 ; USE: r13.8,sp+278.8
48. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+598.8
48. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
48. 0 mov    #0x238D1C151101C288.8, rcx.8 ; 18000B42C u=           d=rcx.8
48. 1 xor    r13.8, (%var_660.8+#0x238D1C151101C288.8), rax.8 ; 18000B439 u=r13.8,sp+278.8 d=rax.8
48. 2 mov    #0.1, cf.1              ; 18000B439 u=           d=cf.1
48. 3 mov    #0.1, of.1              ; 18000B439 u=           d=of.1
48. 4 setz   (r13.8 ^ (%var_660.8+#0x238D1C151101C288.8)), #0.8, zf.1 ; 18000B439 u=r13.8,sp+278.8 d=zf.1
48. 5 setp   (r13.8 ^ (%var_660.8+#0x238D1C151101C288.8)), #0.8, pf.1 ; 18000B439 u=r13.8,sp+278.8 d=pf.1
48. 6 sets   (r13.8 ^ (%var_660.8+#0x238D1C151101C288.8)), sf.1 ; 18000B439 u=r13.8,sp+278.8 d=sf.1
48. 7 xor    r13.8, (%var_660.8+#0x238D1C151101C288.8), %var_340.8 ; 18000B43C u=r13.8,sp+278.8 d=sp+598.8
48. 8 mov    #0x6F.4, %var_8A8.4     ; 18000B444 u=           d=sp+30.4
48. 9 goto   @3                      ; 18000B44C u=
48. 9
49. 0 ; 1WAY-BLOCK 49 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B451 END=18000B487] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
49. 0 ; USE: ds.2,sp+490.9,(GLBLOW,sp+0..490,sp+499..,SHADOW,ARGS,GLBHIGH)
49. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+4A0.8
49. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
49. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000B45C u=           d=rcx.8
49. 1 or     %var_448.8, xdu.8((#0x10000.4*xdu.4([ds.2:(xdu.8((%var_440.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), rax.8 ; 18000B46A u=ds.2,sp+490.9,(GLBLOW,sp+0..490,sp+499..,SHADOW,ARGS,GLBHIGH) d=rax.8
49. 2 mov    #0.1, cf.1              ; 18000B46A u=           d=cf.1
49. 3 mov    #0.1, of.1              ; 18000B46A u=           d=of.1
49. 4 setz   (%var_448.8 | xdu.8((#0x10000.4*xdu.4([ds.2:(xdu.8((%var_440.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)))), #0.8, zf.1 ; 18000B46A u=ds.2,sp+490.9,(GLBLOW,sp+0..490,sp+499..,SHADOW,ARGS,GLBHIGH) d=zf.1
49. 5 setp   (%var_448.8 | xdu.8((#0x10000.4*xdu.4([ds.2:(xdu.8((%var_440.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)))), #0.8, pf.1 ; 18000B46A u=ds.2,sp+490.9,(GLBLOW,sp+0..490,sp+499..,SHADOW,ARGS,GLBHIGH) d=pf.1
49. 6 sets   (%var_448.8 | xdu.8((#0x10000.4*xdu.4([ds.2:(xdu.8((%var_440.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)))), sf.1 ; 18000B46A u=ds.2,sp+490.9,(GLBLOW,sp+0..490,sp+499..,SHADOW,ARGS,GLBHIGH) d=sf.1
49. 7 or     %var_448.8, xdu.8((#0x10000.4*xdu.4([ds.2:(xdu.8((%var_440.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), %var_438.8 ; 18000B472 u=ds.2,sp+490.9,(GLBLOW,sp+0..490,sp+499..,SHADOW,ARGS,GLBHIGH) d=sp+4A0.8
49. 8 mov    #0x51.4, %var_8A8.4     ; 18000B47A u=           d=sp+30.4
49. 9 goto   @3                      ; 18000B482 u=
49. 9
50. 0 ; 1WAY-BLOCK 50 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B487 END=18000B4FB] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
50. 0 ; USE: sp+B8.4
50. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+1E4.4
50. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
50. 0 mov    call !__ROL4__<fast:_DWORD (%var_820.4 ^ #0xC5B1C838.4),char #0xD.1>.4, eax.4 ; 18000B4DC u=sp+B8.4    d=eax.4
50. 1 setz   (eax.4+#0x61AAFA18.4), #0.4, zf.1 ; 18000B4DF u=eax.4      d=zf.1
50. 2 setp   (eax.4+#0x61AAFA18.4), #0.4, pf.1 ; 18000B4DF u=eax.4      d=pf.1
50. 3 sets   (eax.4+#0x61AAFA18.4), sf.1 ; 18000B4DF u=eax.4      d=sf.1
50. 4 add    eax.4, #0x61AAFA18.4, eax.4 ; 18000B4DF u=eax.4      d=eax.4
50. 5 cfshl  eax.4, #5.1, tt.1       ; 18000B4E4 u=eax.4      d=tt.1
50. 6 mov    call !__ROL4__<fast:_DWORD eax.4,char #5.1>.4, eax.4 ; 18000B4E4 u=eax.4      d=eax.4
50. 7 mov    tt.1, cf.1              ; 18000B4E4 u=tt.1       d=cf.1
50. 8 und    of.1                    ; 18000B4E4 u=           d=of.1
50. 9 xdu    eax.4, rax.8            ; 18000B4E4 u=eax.4      d=rax^4.4
50.10 mov    eax.4, %var_6F4.4       ; 18000B4E7 u=eax.4      d=sp+1E4.4
50.11 mov    #0xA5.4, %var_8A8.4     ; 18000B4EE u=           d=sp+30.4
50.12 goto   @3                      ; 18000B4F6 u=
50.12
51. 0 ; 1WAY-BLOCK 51 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B4FB END=18000B612] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
51. 0 ; USE: ds.2,sp+1C4.4,sp+660.8,(GLBLOW,sp+0..1C4,sp+1C8..660,sp+668..,SHADOW,ARGS,GLBHIGH)
51. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+1C8.4
51. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
51. 0 mov    #0.1, cf.1              ; 18000B581 u=           d=cf.1
51. 1 mov    #0.1, of.1              ; 18000B581 u=           d=of.1
51. 2 setz   (%var_714.4 | (#0x10000.4*xdu.4([ds.2:%var_278.8].1))), #0.4, zf.1 ; 18000B581 u=ds.2,sp+1C4.4,sp+660.8,(GLBLOW,sp+0..1C4,sp+1C8..660,sp+668..,SHADOW,ARGS,GLBHIGH) d=zf.1
51. 3 setp   (%var_714.4 | (#0x10000.4*xdu.4([ds.2:%var_278.8].1))), #0.4, pf.1 ; 18000B581 u=ds.2,sp+1C4.4,sp+660.8,(GLBLOW,sp+0..1C4,sp+1C8..660,sp+668..,SHADOW,ARGS,GLBHIGH) d=pf.1
51. 4 sets   (%var_714.4 | (#0x10000.4*xdu.4([ds.2:%var_278.8].1))), sf.1 ; 18000B581 u=ds.2,sp+1C4.4,sp+660.8,(GLBLOW,sp+0..1C4,sp+1C8..660,sp+668..,SHADOW,ARGS,GLBHIGH) d=sf.1
51. 5 xdu    (%var_714.4 | (#0x10000.4*xdu.4([ds.2:%var_278.8].1))), rax.8 ; 18000B581 u=ds.2,sp+1C4.4,sp+660.8,(GLBLOW,sp+0..1C4,sp+1C8..660,sp+668..,SHADOW,ARGS,GLBHIGH) d=rax.8
51. 6 or     %var_714.4, (#0x10000.4*xdu.4([ds.2:%var_278.8].1)), %var_710.4 ; 18000B588 u=ds.2,sp+1C4.4,sp+660.8,(GLBLOW,sp+0..1C4,sp+1C8..660,sp+668..,SHADOW,ARGS,GLBHIGH) d=sp+1C8.4
51. 7 mov    #0x9D.4, %var_8A8.4     ; 18000B605 u=           d=sp+30.4
51. 8 goto   @3                      ; 18000B60D u=
51. 8
52. 0 ; 1WAY-BLOCK 52 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B612 END=18000B6AF] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
52. 0 ; USE: ds.2,sp+18C.4,sp+640.8,(GLBLOW,sp+0..18C,sp+190..640,sp+648..,SHADOW,ARGS,GLBHIGH)
52. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+190.4
52. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
52. 0 mov    #0.1, cf.1              ; 18000B694 u=           d=cf.1
52. 1 mov    #0.1, of.1              ; 18000B694 u=           d=of.1
52. 2 setz   (%var_74C.4 | (#0x100000.4*xdu.4([ds.2:%var_298.8].1))), #0.4, zf.1 ; 18000B694 u=ds.2,sp+18C.4,sp+640.8,(GLBLOW,sp+0..18C,sp+190..640,sp+648..,SHADOW,ARGS,GLBHIGH) d=zf.1
52. 3 setp   (%var_74C.4 | (#0x100000.4*xdu.4([ds.2:%var_298.8].1))), #0.4, pf.1 ; 18000B694 u=ds.2,sp+18C.4,sp+640.8,(GLBLOW,sp+0..18C,sp+190..640,sp+648..,SHADOW,ARGS,GLBHIGH) d=pf.1
52. 4 sets   (%var_74C.4 | (#0x100000.4*xdu.4([ds.2:%var_298.8].1))), sf.1 ; 18000B694 u=ds.2,sp+18C.4,sp+640.8,(GLBLOW,sp+0..18C,sp+190..640,sp+648..,SHADOW,ARGS,GLBHIGH) d=sf.1
52. 5 xdu    (%var_74C.4 | (#0x100000.4*xdu.4([ds.2:%var_298.8].1))), rax.8 ; 18000B694 u=ds.2,sp+18C.4,sp+640.8,(GLBLOW,sp+0..18C,sp+190..640,sp+648..,SHADOW,ARGS,GLBHIGH) d=rax.8
52. 6 or     %var_74C.4, (#0x100000.4*xdu.4([ds.2:%var_298.8].1)), %var_748.4 ; 18000B69B u=ds.2,sp+18C.4,sp+640.8,(GLBLOW,sp+0..18C,sp+190..640,sp+648..,SHADOW,ARGS,GLBHIGH) d=sp+190.4
52. 7 mov    #0x8E.4, %var_8A8.4     ; 18000B6A2 u=           d=sp+30.4
52. 8 goto   @3                      ; 18000B6AA u=
52. 8
53. 0 ; 1WAY-BLOCK 53 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B6AF END=18000B7B4] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
53. 0 ; USE: sp+104.4
53. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+108.4
53. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
53. 0 setz   ((%var_7D4.4 ^ #0x2F642FA8.4)+#0x7B95219B.4), #0.4, zf.1 ; 18000B6BB u=sp+104.4   d=zf.1
53. 1 setp   ((%var_7D4.4 ^ #0x2F642FA8.4)+#0x7B95219B.4), #0.4, pf.1 ; 18000B6BB u=sp+104.4   d=pf.1
53. 2 sets   ((%var_7D4.4 ^ #0x2F642FA8.4)+#0x7B95219B.4), sf.1 ; 18000B6BB u=sp+104.4   d=sf.1
53. 3 add    (%var_7D4.4 ^ #0x2F642FA8.4), #0x7B95219B.4, eax.4 ; 18000B6BB u=sp+104.4   d=eax.4
53. 4 cfshl  eax.4, #0x19.1, tt.1    ; 18000B6C0 u=eax.4      d=tt.1
53. 5 mov    call !__ROL4__<fast:_DWORD eax.4,char #0x19.1>.4, eax.4 ; 18000B6C0 u=eax.4      d=eax.4
53. 6 mov    tt.1, cf.1              ; 18000B6C0 u=tt.1       d=cf.1
53. 7 und    of.1                    ; 18000B6C0 u=           d=of.1
53. 8 xdu    eax.4, rax.8            ; 18000B6C0 u=eax.4      d=rax^4.4
53. 9 mov    eax.4, %var_7D0.4       ; 18000B6C3 u=eax.4      d=sp+108.4
53.10 mov    #0x14.4, %var_8A8.4     ; 18000B7A7 u=           d=sp+30.4
53.11 goto   @3                      ; 18000B7AF u=
53.11
54. 0 ; 1WAY-BLOCK 54 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B7B4 END=18000B84B] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
54. 0 ; USE: ds.2,sp+D8.8,(GLBLOW,sp+0..D8,sp+E0..,SHADOW,ARGS,GLBHIGH)
54. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+134.4,sp+330.8
54. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
54. 0 shr    %var_800.8, #8.1, %var_5A8.8 ; 18000B7C0 u=sp+D8.8    d=sp+330.8
54. 1 mov    &($p_InLoadOrderModuleList_1).8, rcx.8 ; 18000B829 u=           d=rcx.8
54. 2 xdu    [ds.2:(xdu.8((%var_800.2 >>l #0xC.1))+&($p_InLoadOrderModuleList_1).8)].1, eax.4 ; 18000B830 u=ds.2,sp+D8.2,(GLBLOW,sp+0..D8,sp+DA..,SHADOW,ARGS,GLBHIGH) d=eax.4
54. 3 cfshl  eax.4, #0xC.1, cf.1     ; 18000B834 u=eax.4      d=cf.1
54. 4 mul    #0x1000.4, eax.4, eax.4 ; 18000B834 u=eax.4      d=eax.4
54. 5 und    of.1                    ; 18000B834 u=           d=of.1
54. 6 setz   eax.4, #0.4, zf.1       ; 18000B834 u=eax.4      d=zf.1
54. 7 setp   eax.4, #0.4, pf.1       ; 18000B834 u=eax.4      d=pf.1
54. 8 sets   eax.4, sf.1             ; 18000B834 u=eax.4      d=sf.1
54. 9 xdu    eax.4, rax.8            ; 18000B834 u=eax.4      d=rax^4.4
54.10 mov    eax.4, %var_7A4.4       ; 18000B837 u=eax.4      d=sp+134.4
54.11 mov    #0x25.4, %var_8A8.4     ; 18000B83E u=           d=sp+30.4
54.12 goto   @3                      ; 18000B846 u=
54.12
55. 0 ; 1WAY-BLOCK 55 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B84B END=18000B88D] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
55. 0 ; USE: ds.2,sp+60.1,sp+4E8..4F8,(GLBLOW,sp+0..60,sp+61..4E8,sp+4F8..,SHADOW,ARGS,GLBHIGH)
55. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+4F8..508
55. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
55. 0 or     %var_3E8.8, %var_3F0.8, %var_3E0.8 ; 18000B85B u=sp+4E8..4F8 d=sp+4F8.8
55. 1 mov    #0.1, cf.1              ; 18000B86A u=           d=cf.1
55. 2 mov    #0.1, of.1              ; 18000B86A u=           d=of.1
55. 3 setz   xdu.4((%var_878.1 >>l #4.1)), #0.4, zf.1 ; 18000B86A u=sp+60.1    d=zf.1
55. 4 setp   xdu.4((%var_878.1 >>l #4.1)), #0.4, pf.1 ; 18000B86A u=sp+60.1    d=pf.1
55. 5 mov    #0.1, sf.1              ; 18000B86A u=           d=sf.1
55. 6 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000B86D u=           d=rcx.8
55. 7 xdu    [ds.2:(xdu.8((%var_878.1 >>l #4.1))+&($p_InLoadOrderModuleList_5).8)].1, rax.8 ; 18000B874 u=ds.2,sp+60.1,(GLBLOW,sp+0..60,sp+61..,SHADOW,ARGS,GLBHIGH) d=rax.8
55. 8 xdu    [ds.2:(xdu.8((%var_878.1 >>l #4.1))+&($p_InLoadOrderModuleList_5).8)].1, %var_3D8.8 ; 18000B878 u=ds.2,sp+60.1,(GLBLOW,sp+0..60,sp+61..,SHADOW,ARGS,GLBHIGH) d=sp+500.8
55. 9 mov    #0x59.4, %var_8A8.4     ; 18000B880 u=           d=sp+30.4
55.10 goto   @3                      ; 18000B888 u=
55.10
56. 0 ; 1WAY-BLOCK 56 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B88D END=18000B92C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
56. 0 ; USE: sp+130.4
56. 0 ; DEF: rax.8,sp+30.4,sp+D8.8
56. 0 ; DNU: rax.8
56. 0 xdu    %var_7A8.4, rax.8       ; 18000B8CA u=sp+130.4   d=rax.8
56. 1 xdu    %var_7A8.4, %var_800.8  ; 18000B8D1 u=sp+130.4   d=sp+D8.8
56. 2 mov    #0x24.4, %var_8A8.4     ; 18000B91F u=           d=sp+30.4
56. 3 goto   @3                      ; 18000B927 u=
56. 3
57. 0 ; 1WAY-BLOCK 57 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000B92C END=18000BA6C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
57. 0 ; USE: ds.2,sp+60.8,(GLBLOW,sp+0..60,sp+68..,SHADOW,ARGS,GLBHIGH)
57. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+528.8
57. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
57. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000B9E6 u=           d=rcx.8
57. 1 xdu    [ds.2:(((%var_878.8 >>l #0x2C.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1, rax.8 ; 18000B9ED u=ds.2,sp+60.8,(GLBLOW,sp+0..60,sp+68..,SHADOW,ARGS,GLBHIGH) d=rax.8
57. 2 cfshl  rax.8, #0x2C.1, cf.1    ; 18000BA53 u=rax.8      d=cf.1
57. 3 mul    #0x100000000000.8, rax.8, rax.8 ; 18000BA53 u=rax.8      d=rax.8
57. 4 und    of.1                    ; 18000BA53 u=           d=of.1
57. 5 setz   rax.8, #0.8, zf.1       ; 18000BA53 u=rax.8      d=zf.1
57. 6 setp   rax.8, #0.8, pf.1       ; 18000BA53 u=rax.8      d=pf.1
57. 7 sets   rax.8, sf.1             ; 18000BA53 u=rax.8      d=sf.1
57. 8 mov    rax.8, %var_3B0.8       ; 18000BA57 u=rax.8      d=sp+528.8
57. 9 mov    #0x5C.4, %var_8A8.4     ; 18000BA5F u=           d=sp+30.4
57.10 goto   @3                      ; 18000BA67 u=
57.10
58. 0 ; 1WAY-BLOCK 58 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000BA6C END=18000BAA3] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
58. 0 ; USE: ds.2,sp+68.8,(GLBLOW,sp+0..68,sp+70..,SHADOW,ARGS,GLBHIGH)
58. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+5A.1,sp+688.8
58. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
58. 0 shr    %var_870.8, #0x30.1, %var_250.8 ; 18000BA78 u=sp+68.8    d=sp+688.8
58. 1 mov    #0.1, cf.1              ; 18000BA84 u=           d=cf.1
58. 2 mov    #0.1, of.1              ; 18000BA84 u=           d=of.1
58. 3 setz   (low.4((%var_870.8 >>l #0x34.1)) & #0xF.4), #0.4, zf.1 ; 18000BA84 u=sp+68.8    d=zf.1
58. 4 setp   (low.4((%var_870.8 >>l #0x34.1)) & #0xF.4), #0.4, pf.1 ; 18000BA84 u=sp+68.8    d=pf.1
58. 5 mov    #0.1, sf.1              ; 18000BA84 u=           d=sf.1
58. 6 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000BA87 u=           d=rcx.8
58. 7 xdu    [ds.2:(((%var_870.8 >>l #0x34.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1, rax.8 ; 18000BA8E u=ds.2,sp+68.8,(GLBLOW,sp+0..68,sp+70..,SHADOW,ARGS,GLBHIGH) d=rax.8
58. 8 ldx    ds.2, (((%var_870.8 >>l #0x34.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8), %var_87E.1 ; 18000BA92 u=ds.2,sp+68.8,(GLBLOW,sp+0..68,sp+70..,SHADOW,ARGS,GLBHIGH) d=sp+5A.1
58. 9 mov    #0xA9.4, %var_8A8.4     ; 18000BA96 u=           d=sp+30.4
58.10 goto   @3                      ; 18000BA9E u=
58.10
59. 0 ; 1WAY-BLOCK 59 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000BAA3 END=18000BB53] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
59. 0 ; DEF: sp+30.4
59. 0 mov    #0x80.4, %var_8A8.4     ; 18000BB46 u=           d=sp+30.4
59. 1 goto   @3                      ; 18000BB4E u=
59. 1
60. 0 ; 1WAY-BLOCK 60 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000BB53 END=18000BB87] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
60. 0 ; USE: sp+1B0.4
60. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+88.8,sp+1B4.4,sp+650.8
60. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
60. 0 mov    call !__ROL4__<fast:_DWORD %var_728.4,char #0x1A.1>.4, eax.4 ; 18000BB5A u=sp+1B0.4   d=eax.4
60. 1 mov    eax.4, %var_724.4       ; 18000BB5D u=eax.4      d=sp+1B4.4
60. 2 xdu    eax.4, %var_850.8       ; 18000BB64 u=eax.4      d=sp+88.8
60. 3 and    (eax.4 >>l #0x18.1), #0xF.4, eax.4 ; 18000BB6F u=eax.4      d=eax.4
60. 4 mov    #0.1, cf.1              ; 18000BB6F u=           d=cf.1
60. 5 mov    #0.1, of.1              ; 18000BB6F u=           d=of.1
60. 6 setz   eax.4, #0.4, zf.1       ; 18000BB6F u=eax.4      d=zf.1
60. 7 setp   eax.4, #0.4, pf.1       ; 18000BB6F u=eax.4      d=pf.1
60. 8 mov    #0.1, sf.1              ; 18000BB6F u=           d=sf.1
60. 9 xdu    eax.4, rax.8            ; 18000BB6F u=eax.4      d=rax^4.4
60.10 xdu    eax.4, %var_288.8       ; 18000BB72 u=eax.4      d=sp+650.8
60.11 mov    #0x98.4, %var_8A8.4     ; 18000BB7A u=           d=sp+30.4
60.12 goto   @3                      ; 18000BB82 u=
60.12
61. 0 ; 1WAY-BLOCK 61 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000BB87 END=18000BBBB] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
61. 0 ; USE: ds.2,sp+190.4,sp+638.1,(GLBLOW,sp+0..190,sp+194..638,sp+639..,SHADOW,ARGS,GLBHIGH)
61. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+194.4
61. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
61. 0 mov    &($p_InLoadOrderModuleList_6).8, rcx.8 ; 18000BB92 u=           d=rcx.8
61. 1 mov    #0.1, cf.1              ; 18000BBA0 u=           d=cf.1
61. 2 mov    #0.1, of.1              ; 18000BBA0 u=           d=of.1
61. 3 setz   (%var_748.4 | (#0x10000.4*xdu.4([ds.2:(xdu.8((%var_2A0.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1))), #0.4, zf.1 ; 18000BBA0 u=ds.2,sp+190.4,sp+638.1,(GLBLOW,sp+0..190,sp+194..638,sp+639..,SHADOW,ARGS,GLBHIGH) d=zf.1
61. 4 setp   (%var_748.4 | (#0x10000.4*xdu.4([ds.2:(xdu.8((%var_2A0.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1))), #0.4, pf.1 ; 18000BBA0 u=ds.2,sp+190.4,sp+638.1,(GLBLOW,sp+0..190,sp+194..638,sp+639..,SHADOW,ARGS,GLBHIGH) d=pf.1
61. 5 sets   (%var_748.4 | (#0x10000.4*xdu.4([ds.2:(xdu.8((%var_2A0.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1))), sf.1 ; 18000BBA0 u=ds.2,sp+190.4,sp+638.1,(GLBLOW,sp+0..190,sp+194..638,sp+639..,SHADOW,ARGS,GLBHIGH) d=sf.1
61. 6 xdu    (%var_748.4 | (#0x10000.4*xdu.4([ds.2:(xdu.8((%var_2A0.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1))), rax.8 ; 18000BBA0 u=ds.2,sp+190.4,sp+638.1,(GLBLOW,sp+0..190,sp+194..638,sp+639..,SHADOW,ARGS,GLBHIGH) d=rax.8
61. 7 or     %var_748.4, (#0x10000.4*xdu.4([ds.2:(xdu.8((%var_2A0.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1)), %var_744.4 ; 18000BBA7 u=ds.2,sp+190.4,sp+638.1,(GLBLOW,sp+0..190,sp+194..638,sp+639..,SHADOW,ARGS,GLBHIGH) d=sp+194.4
61. 8 mov    #0x8F.4, %var_8A8.4     ; 18000BBAE u=           d=sp+30.4
61. 9 goto   @3                      ; 18000BBB6 u=
61. 9
62. 0 ; 1WAY-BLOCK 62 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000BBBB END=18000BCC2] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
62. 0 ; USE: ds.2,sp+68.8,(GLBLOW,sp+0..68,sp+70..,SHADOW,ARGS,GLBHIGH)
62. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+5B.1,sp+700.8
62. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
62. 0 xdu    %var_870@4.4, %var_1D8.8 ; 18000BBBF u=sp+6C.4    d=sp+700.8
62. 1 mov    #0.1, cf.1              ; 18000BC37 u=           d=cf.1
62. 2 mov    #0.1, of.1              ; 18000BC37 u=           d=of.1
62. 3 setz   (low.4((%var_870.8 >>l #0x24.1)) & #0xF.4), #0.4, zf.1 ; 18000BC37 u=sp+68.8    d=zf.1
62. 4 setp   (low.4((%var_870.8 >>l #0x24.1)) & #0xF.4), #0.4, pf.1 ; 18000BC37 u=sp+68.8    d=pf.1
62. 5 mov    #0.1, sf.1              ; 18000BC37 u=           d=sf.1
62. 6 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000BCA6 u=           d=rcx.8
62. 7 xdu    [ds.2:(((%var_870.8 >>l #0x24.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1, rax.8 ; 18000BCAD u=ds.2,sp+68.8,(GLBLOW,sp+0..68,sp+70..,SHADOW,ARGS,GLBHIGH) d=rax.8
62. 8 ldx    ds.2, (((%var_870.8 >>l #0x24.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8), %var_87D.1 ; 18000BCB1 u=ds.2,sp+68.8,(GLBLOW,sp+0..68,sp+70..,SHADOW,ARGS,GLBHIGH) d=sp+5B.1
62. 9 mov    #0xB2.4, %var_8A8.4     ; 18000BCB5 u=           d=sp+30.4
62.10 goto   @3                      ; 18000BCBD u=
62.10
63. 0 ; 1WAY-BLOCK 63 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000BCC2 END=18000BD05] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
63. 0 ; USE: ds.2,sp+4C8.1,sp+518.8,sp+528.8,(GLBLOW,sp+0..4C8,sp+4C9..518,sp+520.8,sp+530..,SHADOW,ARGS,GLBHIGH)
63. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+530..540
63. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
63. 0 or     %var_3B0.8, %var_3C0.8, %var_3A8.8 ; 18000BCD2 u=sp+518.8,sp+528.8 d=sp+530.8
63. 1 mov    #0.1, cf.1              ; 18000BCE2 u=           d=cf.1
63. 2 mov    #0.1, of.1              ; 18000BCE2 u=           d=of.1
63. 3 setz   xdu.4((%var_410.1 & #0xF.1)), #0.4, zf.1 ; 18000BCE2 u=sp+4C8.1   d=zf.1
63. 4 setp   xdu.4((%var_410.1 & #0xF.1)), #0.4, pf.1 ; 18000BCE2 u=sp+4C8.1   d=pf.1
63. 5 mov    #0.1, sf.1              ; 18000BCE2 u=           d=sf.1
63. 6 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000BCE5 u=           d=rcx.8
63. 7 xdu    [ds.2:(xdu.8((%var_410.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1, rax.8 ; 18000BCEC u=ds.2,sp+4C8.1,(GLBLOW,sp+0..4C8,sp+4C9..,SHADOW,ARGS,GLBHIGH) d=rax.8
63. 8 xdu    [ds.2:(xdu.8((%var_410.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1, %var_3A0.8 ; 18000BCF0 u=ds.2,sp+4C8.1,(GLBLOW,sp+0..4C8,sp+4C9..,SHADOW,ARGS,GLBHIGH) d=sp+538.8
63. 9 mov    #0x5D.4, %var_8A8.4     ; 18000BCF8 u=           d=sp+30.4
63.10 goto   @3                      ; 18000BD00 u=
63.10
64. 0 ; 1WAY-BLOCK 64 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000BD05 END=18000BD42] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
64. 0 ; USE: ds.2,sp+60.8,sp+478.8,sp+488.8,(GLBLOW,sp+0..60,sp+68..478,sp+480.8,sp+490..,SHADOW,ARGS,GLBHIGH)
64. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+490..4A0
64. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
64. 0 or     %var_460.8, (#0x10000000.8*xdu.8([ds.2:%var_450.8].1)), %var_448.8 ; 18000BD1C u=ds.2,sp+478.8,sp+488.8,(GLBLOW,sp+0..478,sp+480.8,sp+490..,SHADOW,ARGS,GLBHIGH) d=sp+490.8
64. 1 cfshr  %var_878.8, #0x10.1, cf.1 ; 18000BD29 u=sp+60.8    d=cf.1
64. 2 shr    %var_878.8, #0x10.1, rax.8 ; 18000BD29 u=sp+60.8    d=rax.8
64. 3 und    of.1                    ; 18000BD29 u=           d=of.1
64. 4 setz   (%var_878.8 >>l #0x10.1), #0.8, zf.1 ; 18000BD29 u=sp+60.8    d=zf.1
64. 5 setp   (%var_878.8 >>l #0x10.1), #0.8, pf.1 ; 18000BD29 u=sp+60.8    d=pf.1
64. 6 mov    #0.1, sf.1              ; 18000BD29 u=           d=sf.1
64. 7 shr    %var_878.8, #0x10.1, %var_440.8 ; 18000BD2D u=sp+60.8    d=sp+498.8
64. 8 mov    #0x50.4, %var_8A8.4     ; 18000BD35 u=           d=sp+30.4
64. 9 goto   @3                      ; 18000BD3D u=
64. 9
65. 0 ; 1WAY-BLOCK 65 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000BD42 END=18000BDC2] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
65. 0 ; USE: ds.2,sp+690.8,sp+6A0.8,(GLBLOW,sp+0..690,sp+698.8,sp+6A8..,SHADOW,ARGS,GLBHIGH)
65. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+6A8.8
65. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
65. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000BD4A u=           d=rcx.8
65. 1 or     %var_248.8, (#0x10000000.8*xdu.8([ds.2:(%var_238.8+&($p_InLoadOrderModuleList_5).8)].1)), rax.8 ; 18000BDA5 u=ds.2,sp+690.8,sp+6A0.8,(GLBLOW,sp+0..690,sp+698.8,sp+6A8..,SHADOW,ARGS,GLBHIGH) d=rax.8
65. 2 mov    #0.1, cf.1              ; 18000BDA5 u=           d=cf.1
65. 3 mov    #0.1, of.1              ; 18000BDA5 u=           d=of.1
65. 4 setz   (%var_248.8 | (#0x10000000.8*xdu.8([ds.2:(%var_238.8+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, zf.1 ; 18000BDA5 u=ds.2,sp+690.8,sp+6A0.8,(GLBLOW,sp+0..690,sp+698.8,sp+6A8..,SHADOW,ARGS,GLBHIGH) d=zf.1
65. 5 setp   (%var_248.8 | (#0x10000000.8*xdu.8([ds.2:(%var_238.8+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, pf.1 ; 18000BDA5 u=ds.2,sp+690.8,sp+6A0.8,(GLBLOW,sp+0..690,sp+698.8,sp+6A8..,SHADOW,ARGS,GLBHIGH) d=pf.1
65. 6 sets   (%var_248.8 | (#0x10000000.8*xdu.8([ds.2:(%var_238.8+&($p_InLoadOrderModuleList_5).8)].1))), sf.1 ; 18000BDA5 u=ds.2,sp+690.8,sp+6A0.8,(GLBLOW,sp+0..690,sp+698.8,sp+6A8..,SHADOW,ARGS,GLBHIGH) d=sf.1
65. 7 or     %var_248.8, (#0x10000000.8*xdu.8([ds.2:(%var_238.8+&($p_InLoadOrderModuleList_5).8)].1)), %var_230.8 ; 18000BDAD u=ds.2,sp+690.8,sp+6A0.8,(GLBLOW,sp+0..690,sp+698.8,sp+6A8..,SHADOW,ARGS,GLBHIGH) d=sp+6A8.8
65. 8 mov    #0xAB.4, %var_8A8.4     ; 18000BDB5 u=           d=sp+30.4
65. 9 goto   @3                      ; 18000BDBD u=
65. 9
66. 0 ; 1WAY-BLOCK 66 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000BDC2 END=18000BE36] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
66. 0 ; USE: ds.2,sp+4E0.1,sp+550.8,(GLBLOW,sp+0..4E0,sp+4E1..550,sp+558..,SHADOW,ARGS,GLBHIGH)
66. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+558.8
66. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
66. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000BDCD u=           d=rcx.8
66. 1 or     %var_388.8, (#0x100000000.8*xdu.8([ds.2:(xdu.8((%var_3F8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)), rax.8 ; 18000BDDC u=ds.2,sp+4E0.1,sp+550.8,(GLBLOW,sp+0..4E0,sp+4E1..550,sp+558..,SHADOW,ARGS,GLBHIGH) d=rax.8
66. 2 mov    #0.1, cf.1              ; 18000BDDC u=           d=cf.1
66. 3 mov    #0.1, of.1              ; 18000BDDC u=           d=of.1
66. 4 setz   (%var_388.8 | (#0x100000000.8*xdu.8([ds.2:(xdu.8((%var_3F8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, zf.1 ; 18000BDDC u=ds.2,sp+4E0.1,sp+550.8,(GLBLOW,sp+0..4E0,sp+4E1..550,sp+558..,SHADOW,ARGS,GLBHIGH) d=zf.1
66. 5 setp   (%var_388.8 | (#0x100000000.8*xdu.8([ds.2:(xdu.8((%var_3F8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, pf.1 ; 18000BDDC u=ds.2,sp+4E0.1,sp+550.8,(GLBLOW,sp+0..4E0,sp+4E1..550,sp+558..,SHADOW,ARGS,GLBHIGH) d=pf.1
66. 6 sets   (%var_388.8 | (#0x100000000.8*xdu.8([ds.2:(xdu.8((%var_3F8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), sf.1 ; 18000BDDC u=ds.2,sp+4E0.1,sp+550.8,(GLBLOW,sp+0..4E0,sp+4E1..550,sp+558..,SHADOW,ARGS,GLBHIGH) d=sf.1
66. 7 or     %var_388.8, (#0x100000000.8*xdu.8([ds.2:(xdu.8((%var_3F8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)), %var_380.8 ; 18000BDE4 u=ds.2,sp+4E0.1,sp+550.8,(GLBLOW,sp+0..4E0,sp+4E1..550,sp+558..,SHADOW,ARGS,GLBHIGH) d=sp+558.8
66. 8 mov    #0x60.4, %var_8A8.4     ; 18000BE29 u=           d=sp+30.4
66. 9 goto   @3                      ; 18000BE31 u=
66. 9
67. 0 ; 1WAY-BLOCK 67 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000BE36 END=18000BEDE] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
67. 0 ; USE: ds.2,sp+88.8,(GLBLOW,sp+0..88,sp+90..,SHADOW,ARGS,GLBHIGH)
67. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+1C0.4,sp+658.8
67. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
67. 0 shr    %var_850.8, #0x10.1, %var_280.8 ; 18000BE42 u=sp+88.8    d=sp+658.8
67. 1 mov    #0.1, cf.1              ; 18000BE54 u=           d=cf.1
67. 2 mov    #0.1, of.1              ; 18000BE54 u=           d=of.1
67. 3 setz   ((%var_850.4 >>l #0x14.1) & #0xF.4), #0.4, zf.1 ; 18000BE54 u=sp+88.4    d=zf.1
67. 4 setp   ((%var_850.4 >>l #0x14.1) & #0xF.4), #0.4, pf.1 ; 18000BE54 u=sp+88.4    d=pf.1
67. 5 mov    #0.1, sf.1              ; 18000BE54 u=           d=sf.1
67. 6 mov    &($p_InLoadOrderModuleList_2).8, rcx.8 ; 18000BE57 u=           d=rcx.8
67. 7 xdu    [ds.2:(xdu.8(((%var_850.4 >>l #0x14.1) & #0xF.4))+&($p_InLoadOrderModuleList_2).8)].1, rax.8 ; 18000BEC6 u=ds.2,sp+88.4,(GLBLOW,sp+0..88,sp+8C..,SHADOW,ARGS,GLBHIGH) d=rax.8
67. 8 xdu    [ds.2:(xdu.8(((%var_850.4 >>l #0x14.1) & #0xF.4))+&($p_InLoadOrderModuleList_2).8)].1, %var_718.4 ; 18000BECA u=ds.2,sp+88.4,(GLBLOW,sp+0..88,sp+8C..,SHADOW,ARGS,GLBHIGH) d=sp+1C0.4
67. 9 mov    #0x9B.4, %var_8A8.4     ; 18000BED1 u=           d=sp+30.4
67.10 goto   @3                      ; 18000BED9 u=
67.10
68. 0 ; 1WAY-BLOCK 68 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000BEDE END=18000BF92] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
68. 0 ; USE: sp+CC.4
68. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+E0.8,sp+7A8..7B8
68. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
68. 0 xdu    %var_80C.4, %var_7F8.8  ; 18000BF5B u=sp+CC.4    d=sp+E0.8
68. 1 xdu    (%var_80C.4 >>l #0x18.1), %var_130.8 ; 18000BF68 u=sp+CC.4    d=sp+7A8.8
68. 2 xdu    (%var_80C.4 >>l #0x1C.1), rax.8 ; 18000BF70 u=sp+CC.4    d=rax.8
68. 3 cfadd  rax.8, &($p_InLoadOrderModuleList_7).8, cf.1 ; 18000BF7A u=rax.8      d=cf.1
68. 4 ofadd  rax.8, &($p_InLoadOrderModuleList_7).8, of.1 ; 18000BF7A u=rax.8      d=of.1
68. 5 setz   (rax.8+&($p_InLoadOrderModuleList_7).8), #0.8, zf.1 ; 18000BF7A u=rax.8      d=zf.1
68. 6 setp   (rax.8+&($p_InLoadOrderModuleList_7).8), #0.8, pf.1 ; 18000BF7A u=rax.8      d=pf.1
68. 7 sets   (rax.8+&($p_InLoadOrderModuleList_7).8), sf.1 ; 18000BF7A u=rax.8      d=sf.1
68. 8 add    rax.8, &($p_InLoadOrderModuleList_7).8, rcx.8 ; 18000BF7A u=rax.8      d=rcx.8
68. 9 add    rax.8, &($p_InLoadOrderModuleList_7).8, %var_128.8 ; 18000BF7D u=rax.8      d=sp+7B0.8
68.10 mov    #0xC6.4, %var_8A8.4     ; 18000BF85 u=           d=sp+30.4
68.11 goto   @3                      ; 18000BF8D u=
68.11
69. 0 ; 1WAY-BLOCK 69 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000BF92 END=18000C06C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
69. 0 ; USE: ds.2,sp+40.8,(GLBLOW,sp+0..40,sp+48..,SHADOW,ARGS,GLBHIGH)
69. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+56.1,sp+3D0.8
69. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
69. 0 shr    %var_898.8, #8.1, %var_508.8 ; 18000BFFE u=sp+40.8    d=sp+3D0.8
69. 1 mov    #0.1, cf.1              ; 18000C00D u=           d=cf.1
69. 2 mov    #0.1, of.1              ; 18000C00D u=           d=of.1
69. 3 setz   xdu.4((%var_898.2 >>l #0xC.1)), #0.4, zf.1 ; 18000C00D u=sp+40.2    d=zf.1
69. 4 setp   xdu.4((%var_898.2 >>l #0xC.1)), #0.4, pf.1 ; 18000C00D u=sp+40.2    d=pf.1
69. 5 mov    #0.1, sf.1              ; 18000C00D u=           d=sf.1
69. 6 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000C050 u=           d=rcx.8
69. 7 xdu    [ds.2:(xdu.8((%var_898.2 >>l #0xC.1))+&($p_InLoadOrderModuleList_5).8)].1, rax.8 ; 18000C057 u=ds.2,sp+40.2,(GLBLOW,sp+0..40,sp+42..,SHADOW,ARGS,GLBHIGH) d=rax.8
69. 8 ldx    ds.2, (xdu.8((%var_898.2 >>l #0xC.1))+&($p_InLoadOrderModuleList_5).8), %var_882.1 ; 18000C05B u=ds.2,sp+40.2,(GLBLOW,sp+0..40,sp+42..,SHADOW,ARGS,GLBHIGH) d=sp+56.1
69. 9 mov    #0x3A.4, %var_8A8.4     ; 18000C05F u=           d=sp+30.4
69.10 goto   @3                      ; 18000C067 u=
69.10
70. 0 ; 1WAY-BLOCK 70 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C06C END=18000C089] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
70. 0 ; USE: sp+450.8
70. 0 ; DEF: rax.8,sp+30.4,sp+458.8
70. 0 ; DNU: rax.8
70. 0 mov    %var_488.8, rax.8       ; 18000C06C u=sp+450.8   d=rax.8
70. 1 mov    %var_488.8, %var_480.8  ; 18000C074 u=sp+450.8   d=sp+458.8
70. 2 mov    #0x47.4, %var_8A8.4     ; 18000C07C u=           d=sp+30.4
70. 3 goto   @3                      ; 18000C084 u=
70. 3
71. 0 ; 1WAY-BLOCK 71 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C089 END=18000C12D] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
71. 0 ; USE: ds.2,sp+3B.1,sp+1CC.8,(GLBLOW,sp+0..3B,sp+3C..1CC,sp+1D4..,SHADOW,ARGS,GLBHIGH)
71. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+59.1,sp+1D4.4
71. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
71. 0 or     %var_708.4, %var_70C.4, %var_704.4 ; 18000C097 u=sp+1CC.8   d=sp+1D4.4
71. 1 cfshr  xdu.4(%var_89D.1), #4.1, cf.1 ; 18000C10E u=sp+3B.1    d=cf.1
71. 2 und    of.1                    ; 18000C10E u=           d=of.1
71. 3 setz   (xdu.4(%var_89D.1) >>l #4.1), #0.4, zf.1 ; 18000C10E u=sp+3B.1    d=zf.1
71. 4 setp   (xdu.4(%var_89D.1) >>l #4.1), #0.4, pf.1 ; 18000C10E u=sp+3B.1    d=pf.1
71. 5 mov    #0.1, sf.1              ; 18000C10E u=           d=sf.1
71. 6 mov    &($p_InLoadOrderModuleList_2).8, rcx.8 ; 18000C111 u=           d=rcx.8
71. 7 xdu    [ds.2:(xdu.8((xdu.4(%var_89D.1) >>l #4.1))+&($p_InLoadOrderModuleList_2).8)].1, rax.8 ; 18000C118 u=ds.2,sp+3B.1,(GLBLOW,sp+0..3B,sp+3C..,SHADOW,ARGS,GLBHIGH) d=rax.8
71. 8 ldx    ds.2, (xdu.8((xdu.4(%var_89D.1) >>l #4.1))+&($p_InLoadOrderModuleList_2).8), %var_87F.1 ; 18000C11C u=ds.2,sp+3B.1,(GLBLOW,sp+0..3B,sp+3C..,SHADOW,ARGS,GLBHIGH) d=sp+59.1
71. 9 mov    #0xA0.4, %var_8A8.4     ; 18000C120 u=           d=sp+30.4
71.10 goto   @3                      ; 18000C128 u=
71.10
72. 0 ; 1WAY-BLOCK 72 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C12D END=18000C1BC] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
72. 0 ; USE: ds.2,sp+330.1,(GLBLOW,sp+0..330,sp+331..,SHADOW,ARGS,GLBHIGH)
72. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+148.4
72. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
72. 0 mov    #0.1, cf.1              ; 18000C19A u=           d=cf.1
72. 1 mov    #0.1, of.1              ; 18000C19A u=           d=of.1
72. 2 setz   xdu.4((%var_5A8.1 & #0xF.1)), #0.4, zf.1 ; 18000C19A u=sp+330.1   d=zf.1
72. 3 setp   xdu.4((%var_5A8.1 & #0xF.1)), #0.4, pf.1 ; 18000C19A u=sp+330.1   d=pf.1
72. 4 mov    #0.1, sf.1              ; 18000C19A u=           d=sf.1
72. 5 mov    &($p_InLoadOrderModuleList_1).8, rcx.8 ; 18000C19D u=           d=rcx.8
72. 6 xdu    [ds.2:(xdu.8((%var_5A8.1 & #0xF.1))+&($p_InLoadOrderModuleList_1).8)].1, rax.8 ; 18000C1A4 u=ds.2,sp+330.1,(GLBLOW,sp+0..330,sp+331..,SHADOW,ARGS,GLBHIGH) d=rax.8
72. 7 xdu    [ds.2:(xdu.8((%var_5A8.1 & #0xF.1))+&($p_InLoadOrderModuleList_1).8)].1, %var_790.4 ; 18000C1A8 u=ds.2,sp+330.1,(GLBLOW,sp+0..330,sp+331..,SHADOW,ARGS,GLBHIGH) d=sp+148.4
72. 8 mov    #0x2B.4, %var_8A8.4     ; 18000C1AF u=           d=sp+30.4
72. 9 goto   @3                      ; 18000C1B7 u=
72. 9
73. 0 ; 1WAY-BLOCK 73 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C1BC END=18000C203] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
73. 0 ; USE: ds.2,sp+E0.8,sp+7E0..7F0,(GLBLOW,sp+0..E0,sp+E8..7E0,sp+7F0..,SHADOW,ARGS,GLBHIGH)
73. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+7F0..800
73. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
73. 0 mov    &($p_InLoadOrderModuleList_7).8, rcx.8 ; 18000C1C4 u=           d=rcx.8
73. 1 or     %var_F8.8, xdu.8((#0x100.4*xdu.4([ds.2:(%var_F0.8+&($p_InLoadOrderModuleList_7).8)].1))), %var_E8.8 ; 18000C1DA u=ds.2,sp+7E0..7F0,(GLBLOW,sp+0..7E0,sp+7F0..,SHADOW,ARGS,GLBHIGH) d=sp+7F0.8
73. 2 cfshr  %var_7F8.8, #0xC.1, cf.1 ; 18000C1EA u=sp+E0.8    d=cf.1
73. 3 shr    %var_7F8.8, #0xC.1, rax.8 ; 18000C1EA u=sp+E0.8    d=rax.8
73. 4 und    of.1                    ; 18000C1EA u=           d=of.1
73. 5 setz   (%var_7F8.8 >>l #0xC.1), #0.8, zf.1 ; 18000C1EA u=sp+E0.8    d=zf.1
73. 6 setp   (%var_7F8.8 >>l #0xC.1), #0.8, pf.1 ; 18000C1EA u=sp+E0.8    d=pf.1
73. 7 mov    #0.1, sf.1              ; 18000C1EA u=           d=sf.1
73. 8 shr    %var_7F8.8, #0xC.1, %var_E0.8 ; 18000C1EE u=sp+E0.8    d=sp+7F8.8
73. 9 mov    #0xCD.4, %var_8A8.4     ; 18000C1F6 u=           d=sp+30.4
73.10 goto   @3                      ; 18000C1FE u=
73.10
74. 0 ; 1WAY-BLOCK 74 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C203 END=18000C294] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
74. 0 ; USE: ds.2,sp+58.1,(GLBLOW,sp+0..58,sp+59..,SHADOW,ARGS,GLBHIGH)
74. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+1A0.4
74. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
74. 0 cfshr  xdu.4(%var_880.1), #4.1, cf.1 ; 18000C208 u=sp+58.1    d=cf.1
74. 1 und    of.1                    ; 18000C208 u=           d=of.1
74. 2 setz   (xdu.4(%var_880.1) >>l #4.1), #0.4, zf.1 ; 18000C208 u=sp+58.1    d=zf.1
74. 3 setp   (xdu.4(%var_880.1) >>l #4.1), #0.4, pf.1 ; 18000C208 u=sp+58.1    d=pf.1
74. 4 mov    #0.1, sf.1              ; 18000C208 u=           d=sf.1
74. 5 mov    &($p_InLoadOrderModuleList_6).8, rcx.8 ; 18000C20B u=           d=rcx.8
74. 6 xdu    [ds.2:(xdu.8((xdu.4(%var_880.1) >>l #4.1))+&($p_InLoadOrderModuleList_6).8)].1, rax.8 ; 18000C27C u=ds.2,sp+58.1,(GLBLOW,sp+0..58,sp+59..,SHADOW,ARGS,GLBHIGH) d=rax.8
74. 7 xdu    [ds.2:(xdu.8((xdu.4(%var_880.1) >>l #4.1))+&($p_InLoadOrderModuleList_6).8)].1, %var_738.4 ; 18000C280 u=ds.2,sp+58.1,(GLBLOW,sp+0..58,sp+59..,SHADOW,ARGS,GLBHIGH) d=sp+1A0.4
74. 8 mov    #0x92.4, %var_8A8.4     ; 18000C287 u=           d=sp+30.4
74. 9 goto   @3                      ; 18000C28F u=
74. 9
75. 0 ; 1WAY-BLOCK 75 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C294 END=18000C340] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
75. 0 ; DEF: sp+30.4
75. 0 mov    #0x15.4, %var_8A8.4     ; 18000C333 u=           d=sp+30.4
75. 1 goto   @3                      ; 18000C33B u=
75. 1
76. 0 ; 1WAY-BLOCK 76 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C340 END=18000C371] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
76. 0 ; USE: ds.2,sp+52.1,sp+12C.4,(GLBLOW,sp+0..52,sp+53..12C,sp+130..,SHADOW,ARGS,GLBHIGH)
76. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+C8.4
76. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
76. 0 mov    &($p_InLoadOrderModuleList_10).8, rcx.8 ; 18000C348 u=           d=rcx.8
76. 1 mov    #0.1, cf.1              ; 18000C356 u=           d=cf.1
76. 2 mov    #0.1, of.1              ; 18000C356 u=           d=of.1
76. 3 setz   (%var_7AC.4 | (#0x10.4*xdu.4([ds.2:(xdu.8((xdu.4(%var_886.1) >>l #4.1))+&($p_InLoadOrderModuleList_10).8)].1))), #0.4, zf.1 ; 18000C356 u=ds.2,sp+52.1,sp+12C.4,(GLBLOW,sp+0..52,sp+53..12C,sp+130..,SHADOW,ARGS,GLBHIGH) d=zf.1
76. 4 setp   (%var_7AC.4 | (#0x10.4*xdu.4([ds.2:(xdu.8((xdu.4(%var_886.1) >>l #4.1))+&($p_InLoadOrderModuleList_10).8)].1))), #0.4, pf.1 ; 18000C356 u=ds.2,sp+52.1,sp+12C.4,(GLBLOW,sp+0..52,sp+53..12C,sp+130..,SHADOW,ARGS,GLBHIGH) d=pf.1
76. 5 sets   (%var_7AC.4 | (#0x10.4*xdu.4([ds.2:(xdu.8((xdu.4(%var_886.1) >>l #4.1))+&($p_InLoadOrderModuleList_10).8)].1))), sf.1 ; 18000C356 u=ds.2,sp+52.1,sp+12C.4,(GLBLOW,sp+0..52,sp+53..12C,sp+130..,SHADOW,ARGS,GLBHIGH) d=sf.1
76. 6 xdu    (%var_7AC.4 | (#0x10.4*xdu.4([ds.2:(xdu.8((xdu.4(%var_886.1) >>l #4.1))+&($p_InLoadOrderModuleList_10).8)].1))), rax.8 ; 18000C356 u=ds.2,sp+52.1,sp+12C.4,(GLBLOW,sp+0..52,sp+53..12C,sp+130..,SHADOW,ARGS,GLBHIGH) d=rax.8
76. 7 or     %var_7AC.4, (#0x10.4*xdu.4([ds.2:(xdu.8((xdu.4(%var_886.1) >>l #4.1))+&($p_InLoadOrderModuleList_10).8)].1)), %var_810.4 ; 18000C35D u=ds.2,sp+52.1,sp+12C.4,(GLBLOW,sp+0..52,sp+53..12C,sp+130..,SHADOW,ARGS,GLBHIGH) d=sp+C8.4
76. 8 mov    #0x21.4, %var_8A8.4     ; 18000C364 u=           d=sp+30.4
76. 9 goto   @3                      ; 18000C36C u=
76. 9
77. 0 ; 1WAY-BLOCK 77 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C371 END=18000C3B8] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
77. 0 ; USE: ds.2,sp+60.8,sp+4D8.8,(GLBLOW,sp+0..60,sp+68..4D8,sp+4E0..,SHADOW,ARGS,GLBHIGH)
77. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+4E0..4F0
77. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
77. 0 shr    %var_878.8, #0x20.1, %var_3F8.8 ; 18000C37D u=sp+60.8    d=sp+4E0.8
77. 1 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000C38C u=           d=rcx.8
77. 2 or     %var_400.8, (#0x1000000000.8*xdu.8([ds.2:(((%var_878.8 >>l #0x24.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1)), rax.8 ; 18000C39B u=ds.2,sp+60.8,sp+4D8.8,(GLBLOW,sp+0..60,sp+68..4D8,sp+4E0..,SHADOW,ARGS,GLBHIGH) d=rax.8
77. 3 mov    #0.1, cf.1              ; 18000C39B u=           d=cf.1
77. 4 mov    #0.1, of.1              ; 18000C39B u=           d=of.1
77. 5 setz   (%var_400.8 | (#0x1000000000.8*xdu.8([ds.2:(((%var_878.8 >>l #0x24.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, zf.1 ; 18000C39B u=ds.2,sp+60.8,sp+4D8.8,(GLBLOW,sp+0..60,sp+68..4D8,sp+4E0..,SHADOW,ARGS,GLBHIGH) d=zf.1
77. 6 setp   (%var_400.8 | (#0x1000000000.8*xdu.8([ds.2:(((%var_878.8 >>l #0x24.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, pf.1 ; 18000C39B u=ds.2,sp+60.8,sp+4D8.8,(GLBLOW,sp+0..60,sp+68..4D8,sp+4E0..,SHADOW,ARGS,GLBHIGH) d=pf.1
77. 7 sets   (%var_400.8 | (#0x1000000000.8*xdu.8([ds.2:(((%var_878.8 >>l #0x24.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1))), sf.1 ; 18000C39B u=ds.2,sp+60.8,sp+4D8.8,(GLBLOW,sp+0..60,sp+68..4D8,sp+4E0..,SHADOW,ARGS,GLBHIGH) d=sf.1
77. 8 or     %var_400.8, (#0x1000000000.8*xdu.8([ds.2:(((%var_878.8 >>l #0x24.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1)), %var_3F0.8 ; 18000C3A3 u=ds.2,sp+60.8,sp+4D8.8,(GLBLOW,sp+0..60,sp+68..4D8,sp+4E0..,SHADOW,ARGS,GLBHIGH) d=sp+4E8.8
77. 9 mov    #0x57.4, %var_8A8.4     ; 18000C3AB u=           d=sp+30.4
77.10 goto   @3                      ; 18000C3B3 u=
77.10
78. 0 ; 1WAY-BLOCK 78 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C3B8 END=18000C49F] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
78. 0 ; USE: ds.2,sp+60.8,(GLBLOW,sp+0..60,sp+68..,SHADOW,ARGS,GLBHIGH)
78. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+468..478
78. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
78. 0 shr    %var_878.8, #0x30.1, %var_470.8 ; 18000C3C4 u=sp+60.8    d=sp+468.8
78. 1 mov    #0.1, cf.1              ; 18000C3D0 u=           d=cf.1
78. 2 mov    #0.1, of.1              ; 18000C3D0 u=           d=of.1
78. 3 setz   (low.4((%var_878.8 >>l #0x34.1)) & #0xF.4), #0.4, zf.1 ; 18000C3D0 u=sp+60.8    d=zf.1
78. 4 setp   (low.4((%var_878.8 >>l #0x34.1)) & #0xF.4), #0.4, pf.1 ; 18000C3D0 u=sp+60.8    d=pf.1
78. 5 mov    #0.1, sf.1              ; 18000C3D0 u=           d=sf.1
78. 6 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000C3D3 u=           d=rcx.8
78. 7 xdu    [ds.2:(((%var_878.8 >>l #0x34.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1, rax.8 ; 18000C3DA u=ds.2,sp+60.8,(GLBLOW,sp+0..60,sp+68..,SHADOW,ARGS,GLBHIGH) d=rax.8
78. 8 xdu    [ds.2:(((%var_878.8 >>l #0x34.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1, %var_468.8 ; 18000C435 u=ds.2,sp+60.8,(GLBLOW,sp+0..60,sp+68..,SHADOW,ARGS,GLBHIGH) d=sp+470.8
78. 9 mov    #0x4E.4, %var_8A8.4     ; 18000C492 u=           d=sp+30.4
78.10 goto   @3                      ; 18000C49A u=
78.10
79. 0 ; 1WAY-BLOCK 79 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C49F END=18000C4D4] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
79. 0 ; USE: ds.2,sp+60.8,sp+558.8,(GLBLOW,sp+0..60,sp+68..558,sp+560..,SHADOW,ARGS,GLBHIGH)
79. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+560.8
79. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
79. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000C4A8 u=           d=rcx.8
79. 1 or     %var_380.8, (#0x1000000000000000.8*xdu.8([ds.2:((%var_878.8 >>l #0x3C.1)+&($p_InLoadOrderModuleList_5).8)].1)), rax.8 ; 18000C4B7 u=ds.2,sp+60.8,sp+558.8,(GLBLOW,sp+0..60,sp+68..558,sp+560..,SHADOW,ARGS,GLBHIGH) d=rax.8
79. 2 mov    #0.1, cf.1              ; 18000C4B7 u=           d=cf.1
79. 3 mov    #0.1, of.1              ; 18000C4B7 u=           d=of.1
79. 4 setz   (%var_380.8 | (#0x1000000000000000.8*xdu.8([ds.2:((%var_878.8 >>l #0x3C.1)+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, zf.1 ; 18000C4B7 u=ds.2,sp+60.8,sp+558.8,(GLBLOW,sp+0..60,sp+68..558,sp+560..,SHADOW,ARGS,GLBHIGH) d=zf.1
79. 5 setp   (%var_380.8 | (#0x1000000000000000.8*xdu.8([ds.2:((%var_878.8 >>l #0x3C.1)+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, pf.1 ; 18000C4B7 u=ds.2,sp+60.8,sp+558.8,(GLBLOW,sp+0..60,sp+68..558,sp+560..,SHADOW,ARGS,GLBHIGH) d=pf.1
79. 6 sets   (%var_380.8 | (#0x1000000000000000.8*xdu.8([ds.2:((%var_878.8 >>l #0x3C.1)+&($p_InLoadOrderModuleList_5).8)].1))), sf.1 ; 18000C4B7 u=ds.2,sp+60.8,sp+558.8,(GLBLOW,sp+0..60,sp+68..558,sp+560..,SHADOW,ARGS,GLBHIGH) d=sf.1
79. 7 or     %var_380.8, (#0x1000000000000000.8*xdu.8([ds.2:((%var_878.8 >>l #0x3C.1)+&($p_InLoadOrderModuleList_5).8)].1)), %var_378.8 ; 18000C4BF u=ds.2,sp+60.8,sp+558.8,(GLBLOW,sp+0..60,sp+68..558,sp+560..,SHADOW,ARGS,GLBHIGH) d=sp+560.8
79. 8 mov    #0x61.4, %var_8A8.4     ; 18000C4C7 u=           d=sp+30.4
79. 9 goto   @3                      ; 18000C4CF u=
79. 9
80. 0 ; 1WAY-BLOCK 80 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C4D4 END=18000C506] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
80. 0 ; USE: sp+600.8,sp+620.8
80. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+628.8
80. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
80. 0 mov    #-0x6B99B175547B836D.8, rcx.8 ; 18000C4E4 u=           d=rcx.8
80. 1 xor    (%var_2D8.8 ^ %var_2B8.8), #-0x6B99B175547B836D.8, rax.8 ; 18000C4EE u=sp+600.8,sp+620.8 d=rax.8
80. 2 mov    #0.1, cf.1              ; 18000C4EE u=           d=cf.1
80. 3 mov    #0.1, of.1              ; 18000C4EE u=           d=of.1
80. 4 setz   ((%var_2D8.8 ^ %var_2B8.8) ^ #-0x6B99B175547B836D.8), #0.8, zf.1 ; 18000C4EE u=sp+600.8,sp+620.8 d=zf.1
80. 5 setp   ((%var_2D8.8 ^ %var_2B8.8) ^ #-0x6B99B175547B836D.8), #0.8, pf.1 ; 18000C4EE u=sp+600.8,sp+620.8 d=pf.1
80. 6 sets   bnot((%var_2D8.8 ^ %var_2B8.8)), sf.1 ; 18000C4EE u=sp+600.8,sp+620.8 d=sf.1
80. 7 xor    (%var_2D8.8 ^ %var_2B8.8), #-0x6B99B175547B836D.8, %var_2B0.8 ; 18000C4F1 u=sp+600.8,sp+620.8 d=sp+628.8
80. 8 mov    #0x86.4, %var_8A8.4     ; 18000C4F9 u=           d=sp+30.4
80. 9 goto   @3                      ; 18000C501 u=
80. 9
81. 0 ; 1WAY-BLOCK 81 INBOUNDS: 4 OUTBOUNDS: 82 [START=18000C506 END=18000C524] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
81. 0 ; USE: rsp.8,(rax.8,rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH)
81. 0 ; DEF: rdx.8,rcx.8,r8.8,r9.8,(cf.1,zf.1,sf.1,of.1,pf.1,rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
81. 0 add    rsp.8, #0x270.8, rdx.8  ; 18000C506 u=rsp.8      d=rdx.8
81. 1 mov    #0x31.8, rcx.8          ; 18000C50E u=           d=rcx.8
81. 2 mov    #0xB.8, r8.8            ; 18000C513 u=           d=r8.8
81. 3 mov    #0x23.8, r9.8           ; 18000C519 u=           d=r9.8
81. 4 call   $sub_1801BCFF0          ; 18000C51F u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
81. 4
82. 0 ; 1WAY-BLOCK 82 INBOUNDS: 81 OUTBOUNDS: 3 [START=18000C524 END=18000C551] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
82. 0 ; USE: r13.8,sp+270.8
82. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+588.8
82. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
82. 0 mov    #0x238D1C151101C288.8, rcx.8 ; 18000C52C u=           d=rcx.8
82. 1 xor    r13.8, (%var_668.8+#0x238D1C151101C288.8), rax.8 ; 18000C539 u=r13.8,sp+270.8 d=rax.8
82. 2 mov    #0.1, cf.1              ; 18000C539 u=           d=cf.1
82. 3 mov    #0.1, of.1              ; 18000C539 u=           d=of.1
82. 4 setz   (r13.8 ^ (%var_668.8+#0x238D1C151101C288.8)), #0.8, zf.1 ; 18000C539 u=r13.8,sp+270.8 d=zf.1
82. 5 setp   (r13.8 ^ (%var_668.8+#0x238D1C151101C288.8)), #0.8, pf.1 ; 18000C539 u=r13.8,sp+270.8 d=pf.1
82. 6 sets   (r13.8 ^ (%var_668.8+#0x238D1C151101C288.8)), sf.1 ; 18000C539 u=r13.8,sp+270.8 d=sf.1
82. 7 xor    r13.8, (%var_668.8+#0x238D1C151101C288.8), %var_350.8 ; 18000C53C u=r13.8,sp+270.8 d=sp+588.8
82. 8 mov    #0x69.4, %var_8A8.4     ; 18000C544 u=           d=sp+30.4
82. 9 goto   @3                      ; 18000C54C u=
82. 9
83. 0 ; 1WAY-BLOCK 83 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C551 END=18000C586] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
83. 0 ; USE: ds.2,sp+184.1,sp+188.4,(GLBLOW,sp+0..184,sp+185.3,sp+18C..,SHADOW,ARGS,GLBHIGH)
83. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+58.1,sp+18C.4
83. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
83. 0 mov    %var_754.1, %var_880.1  ; 18000C559 u=sp+184.1   d=sp+58.1
83. 1 mov    &($p_InLoadOrderModuleList_6).8, rcx.8 ; 18000C560 u=           d=rcx.8
83. 2 mov    #0.1, cf.1              ; 18000C56B u=           d=cf.1
83. 3 mov    #0.1, of.1              ; 18000C56B u=           d=of.1
83. 4 setz   (%var_750.4 | xdu.4([ds.2:(xdu.8((%var_754.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1)), #0.4, zf.1 ; 18000C56B u=ds.2,sp+184.1,sp+188.4,(GLBLOW,sp+0..184,sp+185.3,sp+18C..,SHADOW,ARGS,GLBHIGH) d=zf.1
83. 5 setp   (%var_750.4 | xdu.4([ds.2:(xdu.8((%var_754.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1)), #0.4, pf.1 ; 18000C56B u=ds.2,sp+184.1,sp+188.4,(GLBLOW,sp+0..184,sp+185.3,sp+18C..,SHADOW,ARGS,GLBHIGH) d=pf.1
83. 6 sets   (%var_750.4 | xdu.4([ds.2:(xdu.8((%var_754.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1)), sf.1 ; 18000C56B u=ds.2,sp+184.1,sp+188.4,(GLBLOW,sp+0..184,sp+185.3,sp+18C..,SHADOW,ARGS,GLBHIGH) d=sf.1
83. 7 xdu    (%var_750.4 | xdu.4([ds.2:(xdu.8((%var_754.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1)), rax.8 ; 18000C56B u=ds.2,sp+184.1,sp+188.4,(GLBLOW,sp+0..184,sp+185.3,sp+18C..,SHADOW,ARGS,GLBHIGH) d=rax.8
83. 8 or     %var_750.4, xdu.4([ds.2:(xdu.8((%var_754.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1), %var_74C.4 ; 18000C572 u=ds.2,sp+184.1,sp+188.4,(GLBLOW,sp+0..184,sp+185.3,sp+18C..,SHADOW,ARGS,GLBHIGH) d=sp+18C.4
83. 9 mov    #0x8C.4, %var_8A8.4     ; 18000C579 u=           d=sp+30.4
83.10 goto   @3                      ; 18000C581 u=
83.10
84. 0 ; 1WAY-BLOCK 84 INBOUNDS: 4 OUTBOUNDS: 85 [START=18000C586 END=18000C5C4] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
84. 0 ; USE: rsp.8,sp+628.8,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..628,sp+630..,SHADOW,ARGS,GLBHIGH)
84. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,sp+2A8.8,(r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..2A8,sp+2B0..,RET,SHADOW,ARGS,GLBHIGH)
84. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
84. 0 setz   %var_2B0.8, #0x66CA5D084149E18.8, zf.1 ; 18000C598 u=sp+628.8   d=zf.1
84. 1 setp   %var_2B0.8, #0x66CA5D084149E18.8, pf.1 ; 18000C598 u=sp+628.8   d=pf.1
84. 2 sets   (%var_2B0.8-#0x66CA5D084149E18.8), sf.1 ; 18000C598 u=sp+628.8   d=sf.1
84. 3 mov    call !__ROL8__<fast:_QWORD (%var_2B0.8-#0x66CA5D084149E18.8),char #0x39.1>.8, rax.8 ; 18000C59B u=sp+628.8   d=rax.8
84. 4 cfshl  (%var_2B0.8-#0x66CA5D084149E18.8), #0x39.1, cf.1 ; 18000C59B u=sp+628.8   d=cf.1
84. 5 und    of.1                    ; 18000C59B u=           d=of.1
84. 6 mov    rax.8, %var_630.8       ; 18000C59F u=rax.8      d=sp+2A8.8
84. 7 add    rsp.8, #0x2A8.8, r9.8   ; 18000C5A7 u=rsp.8      d=r9.8
84. 8 mov    #0x49.8, rcx.8          ; 18000C5AF u=           d=rcx.8
84. 9 mov    #0x4D.8, rdx.8          ; 18000C5B4 u=           d=rdx.8
84.10 mov    #0x31.8, r8.8           ; 18000C5B9 u=           d=r8.8
84.11 call   $sub_18007FE10          ; 18000C5BF u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
84.11
85. 0 ; 1WAY-BLOCK 85 INBOUNDS: 84 OUTBOUNDS: 3 [START=18000C5C4 END=18000C5D1] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
85. 0 ; DEF: sp+30.4
85. 0 mov    #0x87.4, %var_8A8.4     ; 18000C5C4 u=           d=sp+30.4
85. 1 goto   @3                      ; 18000C5CC u=
85. 1
86. 0 ; 1WAY-BLOCK 86 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C5D1 END=18000C608] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
86. 0 ; USE: ds.2,sp+688.1,sp+728.8,(GLBLOW,sp+0..688,sp+689..728,sp+730..,SHADOW,ARGS,GLBHIGH)
86. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+730.8
86. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
86. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000C5DC u=           d=rcx.8
86. 1 or     %var_1B0.8, (#0x1000000000000.8*xdu.8([ds.2:(xdu.8((%var_250.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)), rax.8 ; 18000C5EB u=ds.2,sp+688.1,sp+728.8,(GLBLOW,sp+0..688,sp+689..728,sp+730..,SHADOW,ARGS,GLBHIGH) d=rax.8
86. 2 mov    #0.1, cf.1              ; 18000C5EB u=           d=cf.1
86. 3 mov    #0.1, of.1              ; 18000C5EB u=           d=of.1
86. 4 setz   (%var_1B0.8 | (#0x1000000000000.8*xdu.8([ds.2:(xdu.8((%var_250.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, zf.1 ; 18000C5EB u=ds.2,sp+688.1,sp+728.8,(GLBLOW,sp+0..688,sp+689..728,sp+730..,SHADOW,ARGS,GLBHIGH) d=zf.1
86. 5 setp   (%var_1B0.8 | (#0x1000000000000.8*xdu.8([ds.2:(xdu.8((%var_250.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, pf.1 ; 18000C5EB u=ds.2,sp+688.1,sp+728.8,(GLBLOW,sp+0..688,sp+689..728,sp+730..,SHADOW,ARGS,GLBHIGH) d=pf.1
86. 6 sets   (%var_1B0.8 | (#0x1000000000000.8*xdu.8([ds.2:(xdu.8((%var_250.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), sf.1 ; 18000C5EB u=ds.2,sp+688.1,sp+728.8,(GLBLOW,sp+0..688,sp+689..728,sp+730..,SHADOW,ARGS,GLBHIGH) d=sf.1
86. 7 or     %var_1B0.8, (#0x1000000000000.8*xdu.8([ds.2:(xdu.8((%var_250.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)), %var_1A8.8 ; 18000C5F3 u=ds.2,sp+688.1,sp+728.8,(GLBLOW,sp+0..688,sp+689..728,sp+730..,SHADOW,ARGS,GLBHIGH) d=sp+730.8
86. 8 mov    #0xB6.4, %var_8A8.4     ; 18000C5FB u=           d=sp+30.4
86. 9 goto   @3                      ; 18000C603 u=
86. 9
87. 0 ; 1WAY-BLOCK 87 INBOUNDS: 4 OUTBOUNDS: 88 [START=18000C608 END=18000C67E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
87. 0 ; USE: rsp.8,sp+680.8,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..680,sp+688..,SHADOW,ARGS,GLBHIGH)
87. 0 ; DEF: rax.16,rcx.8,r8.8,r9.8,sp+260.8,(cf.1,zf.1,sf.1,of.1,pf.1,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm4.16,xmm5.16,GLBLOW,sp+0..260,sp+268..,RET,SHADOW,ARGS,GLBHIGH)
87. 0 mov    %var_258.8, rax.8       ; 18000C608 u=sp+680.8   d=rax.8
87. 1 mov    %var_258.8, %var_678.8  ; 18000C610 u=sp+680.8   d=sp+260.8
87. 2 add    rsp.8, #0x260.8, rdx.8  ; 18000C660 u=rsp.8      d=rdx.8
87. 3 mov    #0x51.8, rcx.8          ; 18000C668 u=           d=rcx.8
87. 4 mov    #0x45.8, r8.8           ; 18000C66D u=           d=r8.8
87. 5 mov    #0x58.8, r9.8           ; 18000C673 u=           d=r9.8
87. 6 call   $sub_1800A91F0          ; 18000C679 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm4.16,xmm5.16,ALLMEM)
87. 6
88. 0 ; 1WAY-BLOCK 88 INBOUNDS: 87 OUTBOUNDS: 3 [START=18000C67E END=18000C6E9] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
88. 0 ; USE: rdi.8,sp+260.8
88. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+68.8
88. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
88. 0 mov    call !__ROL8__<fast:_QWORD %var_678.8,char #0x35.1>.8, rax.8 ; 18000C686 u=sp+260.8   d=rax.8
88. 1 cfadd  rdi.8, rax.8, cf.1      ; 18000C68A u=rax.8,rdi.8 d=cf.1
88. 2 ofadd  rdi.8, rax.8, of.1      ; 18000C68A u=rax.8,rdi.8 d=of.1
88. 3 setz   (rdi.8+rax.8), #0.8, zf.1 ; 18000C68A u=rax.8,rdi.8 d=zf.1
88. 4 setp   (rdi.8+rax.8), #0.8, pf.1 ; 18000C68A u=rax.8,rdi.8 d=pf.1
88. 5 sets   (rdi.8+rax.8), sf.1     ; 18000C68A u=rax.8,rdi.8 d=sf.1
88. 6 add    rdi.8, rax.8, rax.8     ; 18000C68A u=rax.8,rdi.8 d=rax.8
88. 7 mov    rax.8, %var_870.8       ; 18000C68D u=rax.8      d=sp+68.8
88. 8 mov    #0xA8.4, %var_8A8.4     ; 18000C6DC u=           d=sp+30.4
88. 9 goto   @3                      ; 18000C6E4 u=
88. 9
89. 0 ; 1WAY-BLOCK 89 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C6E9 END=18000C7E9] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
89. 0 ; USE: ds.2,sp+6E0.8,sp+6F0.1,(GLBLOW,sp+0..6E0,sp+6E8.8,sp+6F1..,SHADOW,ARGS,GLBHIGH)
89. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+6F8.8
89. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
89. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000C764 u=           d=rcx.8
89. 1 or     %var_1F8.8, xdu.8((#0x1000.4*xdu.4([ds.2:(xdu.8((%var_1E8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), rax.8 ; 18000C772 u=ds.2,sp+6E0.8,sp+6F0.1,(GLBLOW,sp+0..6E0,sp+6E8.8,sp+6F1..,SHADOW,ARGS,GLBHIGH) d=rax.8
89. 2 mov    #0.1, cf.1              ; 18000C772 u=           d=cf.1
89. 3 mov    #0.1, of.1              ; 18000C772 u=           d=of.1
89. 4 setz   (%var_1F8.8 | xdu.8((#0x1000.4*xdu.4([ds.2:(xdu.8((%var_1E8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)))), #0.8, zf.1 ; 18000C772 u=ds.2,sp+6E0.8,sp+6F0.1,(GLBLOW,sp+0..6E0,sp+6E8.8,sp+6F1..,SHADOW,ARGS,GLBHIGH) d=zf.1
89. 5 setp   (%var_1F8.8 | xdu.8((#0x1000.4*xdu.4([ds.2:(xdu.8((%var_1E8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)))), #0.8, pf.1 ; 18000C772 u=ds.2,sp+6E0.8,sp+6F0.1,(GLBLOW,sp+0..6E0,sp+6E8.8,sp+6F1..,SHADOW,ARGS,GLBHIGH) d=pf.1
89. 6 sets   (%var_1F8.8 | xdu.8((#0x1000.4*xdu.4([ds.2:(xdu.8((%var_1E8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)))), sf.1 ; 18000C772 u=ds.2,sp+6E0.8,sp+6F0.1,(GLBLOW,sp+0..6E0,sp+6E8.8,sp+6F1..,SHADOW,ARGS,GLBHIGH) d=sf.1
89. 7 or     %var_1F8.8, xdu.8((#0x1000.4*xdu.4([ds.2:(xdu.8((%var_1E8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), %var_1E0.8 ; 18000C77A u=ds.2,sp+6E0.8,sp+6F0.1,(GLBLOW,sp+0..6E0,sp+6E8.8,sp+6F1..,SHADOW,ARGS,GLBHIGH) d=sp+6F8.8
89. 8 mov    #0xB1.4, %var_8A8.4     ; 18000C7DC u=           d=sp+30.4
89. 9 goto   @3                      ; 18000C7E4 u=
89. 9
90. 0 ; 1WAY-BLOCK 90 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C7E9 END=18000C81A] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
90. 0 ; USE: sp+1F4.8
90. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+1FC.4
90. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
90. 0 mul    #0x1B873593.4, (%var_6E0.4 | (%var_6E4.4 >>l #0x11.1)), eax.4 ; 18000C7FA split4 u=sp+1F4.8   d=eax.4
90. 1 und    zf.1                    ; 18000C7FA u=           d=zf.1
90. 2 und    sf.1                    ; 18000C7FA u=           d=sf.1
90. 3 und    pf.1                    ; 18000C7FA u=           d=pf.1
90. 4 cfshl  eax.4, #0xD.1, tt.1     ; 18000C800 u=eax.4      d=tt.1
90. 5 mov    call !__ROL4__<fast:_DWORD eax.4,char #0xD.1>.4, eax.4 ; 18000C800 u=eax.4      d=eax.4
90. 6 mov    tt.1, cf.1              ; 18000C800 u=tt.1       d=cf.1
90. 7 und    of.1                    ; 18000C800 u=           d=of.1
90. 8 xdu    (#5.4*eax.4), rax.8     ; 18000C803 u=eax.4      d=rax.8
90. 9 mov    eax.4, %var_6DC.4       ; 18000C806 u=eax.4      d=sp+1FC.4
90.10 mov    #0xD3.4, %var_8A8.4     ; 18000C80D u=           d=sp+30.4
90.11 goto   @3                      ; 18000C815 u=
90.11
91. 0 ; 1WAY-BLOCK 91 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C81A END=18000C8A5] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
91. 0 ; USE: ds.2,sp+7A0.8,(GLBLOW,sp+0..7A0,sp+7A8..,SHADOW,ARGS,GLBHIGH)
91. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+1F0.4
91. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
91. 0 mov    %var_138.8, rax.8       ; 18000C81A u=sp+7A0.8   d=rax.8
91. 1 mov    #0.1, cf.1              ; 18000C88B u=           d=cf.1
91. 2 mov    #0.1, of.1              ; 18000C88B u=           d=of.1
91. 3 setz   (([ds.2:%var_138.8].4+#0x3F16914D.4) ^ #0xA7F45DB.4), #0.4, zf.1 ; 18000C88B u=ds.2,sp+7A0.8,(GLBLOW,sp+0..7A0,sp+7A8..,SHADOW,ARGS,GLBHIGH) d=zf.1
91. 4 setp   (([ds.2:%var_138.8].4+#0x3F16914D.4) ^ #0xA7F45DB.4), #0.4, pf.1 ; 18000C88B u=ds.2,sp+7A0.8,(GLBLOW,sp+0..7A0,sp+7A8..,SHADOW,ARGS,GLBHIGH) d=pf.1
91. 5 sets   ([ds.2:%var_138.8].4+#0x3F16914D.4), sf.1 ; 18000C88B u=ds.2,sp+7A0.8,(GLBLOW,sp+0..7A0,sp+7A8..,SHADOW,ARGS,GLBHIGH) d=sf.1
91. 6 xdu    (([ds.2:%var_138.8].4+#0x3F16914D.4) ^ #0xA7F45DB.4), rcx.8 ; 18000C88B u=ds.2,sp+7A0.8,(GLBLOW,sp+0..7A0,sp+7A8..,SHADOW,ARGS,GLBHIGH) d=rcx.8
91. 7 xor    ([ds.2:%var_138.8].4+#0x3F16914D.4), #0xA7F45DB.4, %var_6E8.4 ; 18000C891 u=ds.2,sp+7A0.8,(GLBLOW,sp+0..7A0,sp+7A8..,SHADOW,ARGS,GLBHIGH) d=sp+1F0.4
91. 8 mov    #0xC3.4, %var_8A8.4     ; 18000C898 u=           d=sp+30.4
91. 9 goto   @3                      ; 18000C8A0 u=
91. 9
92. 0 ; 1WAY-BLOCK 92 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C8A5 END=18000C9A1] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
92. 0 ; USE: sp+80.8
92. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+638..648
92. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
92. 0 shr    %var_858.8, #0x10.1, %var_2A0.8 ; 18000C8B1 u=sp+80.8    d=sp+638.8
92. 1 xdu    ((%var_858.4 >>l #0x14.1) & #0xF.4), rax.8 ; 18000C8C3 u=sp+80.4    d=rax.8
92. 2 cfadd  rax.8, &($p_InLoadOrderModuleList_6).8, cf.1 ; 18000C942 u=rax.8      d=cf.1
92. 3 ofadd  rax.8, &($p_InLoadOrderModuleList_6).8, of.1 ; 18000C942 u=rax.8      d=of.1
92. 4 setz   (rax.8+&($p_InLoadOrderModuleList_6).8), #0.8, zf.1 ; 18000C942 u=rax.8      d=zf.1
92. 5 setp   (rax.8+&($p_InLoadOrderModuleList_6).8), #0.8, pf.1 ; 18000C942 u=rax.8      d=pf.1
92. 6 sets   (rax.8+&($p_InLoadOrderModuleList_6).8), sf.1 ; 18000C942 u=rax.8      d=sf.1
92. 7 add    rax.8, &($p_InLoadOrderModuleList_6).8, rcx.8 ; 18000C942 u=rax.8      d=rcx.8
92. 8 add    rax.8, &($p_InLoadOrderModuleList_6).8, %var_298.8 ; 18000C945 u=rax.8      d=sp+640.8
92. 9 mov    #0x8D.4, %var_8A8.4     ; 18000C994 u=           d=sp+30.4
92.10 goto   @3                      ; 18000C99C u=
92.10
93. 0 ; 1WAY-BLOCK 93 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000C9A1 END=18000CA21] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
93. 0 ; USE: ds.2,sp+E2.1,sp+7C0.8,(GLBLOW,sp+0..E2,sp+E3..7C0,sp+7C8..,SHADOW,ARGS,GLBHIGH)
93. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+7C8.8
93. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
93. 0 mov    &($p_InLoadOrderModuleList_7).8, rcx.8 ; 18000C9AC u=           d=rcx.8
93. 1 or     %var_118.8, xdu.8((#0x10000.4*xdu.4([ds.2:(xdu.8((%var_7F8@2.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1))), rax.8 ; 18000CA04 u=ds.2,sp+E2.1,sp+7C0.8,(GLBLOW,sp+0..E2,sp+E3..7C0,sp+7C8..,SHADOW,ARGS,GLBHIGH) d=rax.8
93. 2 mov    #0.1, cf.1              ; 18000CA04 u=           d=cf.1
93. 3 mov    #0.1, of.1              ; 18000CA04 u=           d=of.1
93. 4 setz   (%var_118.8 | xdu.8((#0x10000.4*xdu.4([ds.2:(xdu.8((%var_7F8@2.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1)))), #0.8, zf.1 ; 18000CA04 u=ds.2,sp+E2.1,sp+7C0.8,(GLBLOW,sp+0..E2,sp+E3..7C0,sp+7C8..,SHADOW,ARGS,GLBHIGH) d=zf.1
93. 5 setp   (%var_118.8 | xdu.8((#0x10000.4*xdu.4([ds.2:(xdu.8((%var_7F8@2.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1)))), #0.8, pf.1 ; 18000CA04 u=ds.2,sp+E2.1,sp+7C0.8,(GLBLOW,sp+0..E2,sp+E3..7C0,sp+7C8..,SHADOW,ARGS,GLBHIGH) d=pf.1
93. 6 sets   (%var_118.8 | xdu.8((#0x10000.4*xdu.4([ds.2:(xdu.8((%var_7F8@2.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1)))), sf.1 ; 18000CA04 u=ds.2,sp+E2.1,sp+7C0.8,(GLBLOW,sp+0..E2,sp+E3..7C0,sp+7C8..,SHADOW,ARGS,GLBHIGH) d=sf.1
93. 7 or     %var_118.8, xdu.8((#0x10000.4*xdu.4([ds.2:(xdu.8((%var_7F8@2.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1))), %var_110.8 ; 18000CA0C u=ds.2,sp+E2.1,sp+7C0.8,(GLBLOW,sp+0..E2,sp+E3..7C0,sp+7C8..,SHADOW,ARGS,GLBHIGH) d=sp+7C8.8
93. 8 mov    #0xC9.4, %var_8A8.4     ; 18000CA14 u=           d=sp+30.4
93. 9 goto   @3                      ; 18000CA1C u=
93. 9
94. 0 ; 1WAY-BLOCK 94 INBOUNDS: 4 OUTBOUNDS: 95 [START=18000CA21 END=18000CA3E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
94. 0 ; USE: rsp.8,(rax.8,rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH)
94. 0 ; DEF: rdx.8,rcx.8,r8.8,r9.8,(cf.1,zf.1,sf.1,of.1,pf.1,rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
94. 0 add    rsp.8, #0xA8.8, r9.8    ; 18000CA21 u=rsp.8      d=r9.8
94. 1 mov    #0xE.8, rcx.8           ; 18000CA29 u=           d=rcx.8
94. 2 mov    #0xC.8, rdx.8           ; 18000CA2E u=           d=rdx.8
94. 3 mov    #0x1B.8, r8.8           ; 18000CA33 u=           d=r8.8
94. 4 call   $sub_18013CC60          ; 18000CA39 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
94. 4
95. 0 ; 1WAY-BLOCK 95 INBOUNDS: 94 OUTBOUNDS: 3 [START=18000CA3E END=18000CA72] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
95. 0 ; USE: sp+A8.4,sp+788.8
95. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+1EC.4,sp+790.8
95. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
95. 0 sub    %var_830.4, #0x425E0292.4, %var_6EC.4 ; 18000CA4A u=sp+A8.4    d=sp+1EC.4
95. 1 cfadd  %var_150.8, #0x5C.8, cf.1 ; 18000CA59 u=sp+788.8   d=cf.1
95. 2 ofadd  #0x5C.8, %var_150.8, of.1 ; 18000CA59 u=sp+788.8   d=of.1
95. 3 setz   (%var_150.8+#0x5C.8), #0.8, zf.1 ; 18000CA59 u=sp+788.8   d=zf.1
95. 4 setp   (%var_150.8+#0x5C.8), #0.8, pf.1 ; 18000CA59 u=sp+788.8   d=pf.1
95. 5 sets   (%var_150.8+#0x5C.8), sf.1 ; 18000CA59 u=sp+788.8   d=sf.1
95. 6 add    %var_150.8, #0x5C.8, rax.8 ; 18000CA59 u=sp+788.8   d=rax.8
95. 7 add    %var_150.8, #0x5C.8, %var_148.8 ; 18000CA5D u=sp+788.8   d=sp+790.8
95. 8 mov    #0xC0.4, %var_8A8.4     ; 18000CA65 u=           d=sp+30.4
95. 9 goto   @3                      ; 18000CA6D u=
95. 9
96. 0 ; 1WAY-BLOCK 96 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000CA72 END=18000CA9F] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
96. 0 ; USE: ds.2,sp+68.4,(GLBLOW,sp+0..68,sp+6C..,SHADOW,ARGS,GLBHIGH)
96. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+6B8.8
96. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
96. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000CA7C u=           d=rcx.8
96. 1 xdu    [ds.2:(xdu.8(((%var_870.4 >>l #0x14.1) & #0xF.4))+&($p_InLoadOrderModuleList_5).8)].1, eax.4 ; 18000CA83 u=ds.2,sp+68.4,(GLBLOW,sp+0..68,sp+6C..,SHADOW,ARGS,GLBHIGH) d=eax.4
96. 2 cfshl  eax.4, #0x14.1, cf.1    ; 18000CA87 u=eax.4      d=cf.1
96. 3 mul    #0x100000.4, eax.4, eax.4 ; 18000CA87 u=eax.4      d=eax.4
96. 4 und    of.1                    ; 18000CA87 u=           d=of.1
96. 5 setz   eax.4, #0.4, zf.1       ; 18000CA87 u=eax.4      d=zf.1
96. 6 setp   eax.4, #0.4, pf.1       ; 18000CA87 u=eax.4      d=pf.1
96. 7 sets   eax.4, sf.1             ; 18000CA87 u=eax.4      d=sf.1
96. 8 xdu    eax.4, rax.8            ; 18000CA87 u=eax.4      d=rax^4.4
96. 9 xdu    eax.4, %var_220.8       ; 18000CA8A u=eax.4      d=sp+6B8.8
96.10 mov    #0xAD.4, %var_8A8.4     ; 18000CA92 u=           d=sp+30.4
96.11 goto   @3                      ; 18000CA9A u=
96.11
97. 0 ; 1WAY-BLOCK 97 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000CA9F END=18000CB22] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
97. 0 ; USE: sp+204.4
97. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+208.8
97. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
97. 0 xdu    (#0x16A88000.4*%var_6D4.4), rax.8 ; 18000CAAC u=sp+204.4   d=rax.8
97. 1 mul    #0x16A88000.4, %var_6D4.4, %var_6D0.4 ; 18000CAB2 split4 u=sp+204.4   d=sp+208.4
97. 2 cfshr  (#0xCC9E2D51.4*%var_6D4.4), #0x11.1, cf.1 ; 18000CB0B u=sp+204.4   d=cf.1
97. 3 und    of.1                    ; 18000CB0B u=           d=of.1
97. 4 setz   ((#0xCC9E2D51.4*%var_6D4.4) >>l #0x11.1), #0.4, zf.1 ; 18000CB0B u=sp+204.4   d=zf.1
97. 5 setp   ((#0xCC9E2D51.4*%var_6D4.4) >>l #0x11.1), #0.4, pf.1 ; 18000CB0B u=sp+204.4   d=pf.1
97. 6 mov    #0.1, sf.1              ; 18000CB0B u=           d=sf.1
97. 7 xdu    ((#0xCC9E2D51.4*%var_6D4.4) >>l #0x11.1), rcx.8 ; 18000CB0B u=sp+204.4   d=rcx.8
97. 8 shr    (#0xCC9E2D51.4*%var_6D4.4), #0x11.1, %var_6CC.4 ; 18000CB0E u=sp+204.4   d=sp+20C.4
97. 9 mov    #0xD5.4, %var_8A8.4     ; 18000CB15 u=           d=sp+30.4
97.10 goto   @3                      ; 18000CB1D u=
97.10
98. 0 ; 1WAY-BLOCK 98 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000CB22 END=18000CB54] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
98. 0 ; USE: ds.2,sp+1FC.4,sp+2D8.8,(GLBLOW,sp+0..1FC,sp+200..2D8,sp+2E0..,SHADOW,ARGS,GLBHIGH)
98. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+200.8
98. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
98. 0 cfadd  %var_6DC.4, #0xE6546B64.4, cf.1 ; 18000CB27 u=sp+1FC.4   d=cf.1
98. 1 ofadd  %var_6DC.4, #0xE6546B64.4, of.1 ; 18000CB27 u=sp+1FC.4   d=of.1
98. 2 setz   %var_6DC.4, #0x19AB949C.4, zf.1 ; 18000CB27 u=sp+1FC.4   d=zf.1
98. 3 setp   %var_6DC.4, #0x19AB949C.4, pf.1 ; 18000CB27 u=sp+1FC.4   d=pf.1
98. 4 sets   (%var_6DC.4-#0x19AB949C.4), sf.1 ; 18000CB27 u=sp+1FC.4   d=sf.1
98. 5 sub    %var_6DC.4, #0x19AB949C.4, %var_6D8.4 ; 18000CB2E u=sp+1FC.4   d=sp+200.4
98. 6 xdu    [ds.2:(%var_600.8+#4.8)].4, rax.8 ; 18000CB3D u=ds.2,sp+2D8.8,(GLBLOW,sp+0..2D8,sp+2E0..,SHADOW,ARGS,GLBHIGH) d=rax.8
98. 7 ldx    ds.2, (%var_600.8+#4.8), %var_6D4.4 ; 18000CB40 u=ds.2,sp+2D8.8,(GLBLOW,sp+0..2D8,sp+2E0..,SHADOW,ARGS,GLBHIGH) d=sp+204.4
98. 8 mov    #0xD4.4, %var_8A8.4     ; 18000CB47 u=           d=sp+30.4
98. 9 goto   @3                      ; 18000CB4F u=
98. 9
99. 0 ; 1WAY-BLOCK 99 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000CB54 END=18000CBD9] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
99. 0 ; USE: sp+168.4
99. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+16C.4
99. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
99. 0 mov    call !__ROL4__<fast:_DWORD %var_770.4,char #0x13.1>.4, eax.4 ; 18000CBB5 u=sp+168.4   d=eax.4
99. 1 mov    call !__ROL4__<fast:_DWORD (eax.4 ^ #0xFCAB611B.4),char #9.1>.4, eax.4 ; 18000CBBD u=eax.4      d=eax.4
99. 2 cfadd  eax.4, #0x4CC071E0.4, cf.1 ; 18000CBC0 u=eax.4      d=cf.1
99. 3 ofadd  #0x4CC071E0.4, eax.4, of.1 ; 18000CBC0 u=eax.4      d=of.1
99. 4 setz   (eax.4+#0x4CC071E0.4), #0.4, zf.1 ; 18000CBC0 u=eax.4      d=zf.1
99. 5 setp   (eax.4+#0x4CC071E0.4), #0.4, pf.1 ; 18000CBC0 u=eax.4      d=pf.1
99. 6 sets   (eax.4+#0x4CC071E0.4), sf.1 ; 18000CBC0 u=eax.4      d=sf.1
99. 7 xdu    (eax.4+#0x4CC071E0.4), rax.8 ; 18000CBC0 u=eax.4      d=rax.8
99. 8 mov    eax.4, %var_76C.4       ; 18000CBC5 u=eax.4      d=sp+16C.4
99. 9 mov    #0x6D.4, %var_8A8.4     ; 18000CBCC u=           d=sp+30.4
99.10 goto   @3                      ; 18000CBD4 u=
99.10
100. 0 ; 1WAY-BLOCK 100 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000CBD9 END=18000CCC7] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
100. 0 ; USE: sp+570.8
100. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+578.8
100. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
100. 0 setz   (%var_368.8 ^ #-0x3FE24F4BC9EA5E45.8), #0.8, zf.1 ; 18000CC39 u=sp+570.8   d=zf.1
100. 1 setp   (%var_368.8 ^ #-0x3FE24F4BC9EA5E45.8), #0.8, pf.1 ; 18000CC39 u=sp+570.8   d=pf.1
100. 2 sets   bnot(%var_368.8), sf.1  ; 18000CC39 u=sp+570.8   d=sf.1
100. 3 mov    call !__ROL8__<fast:_QWORD (%var_368.8 ^ #-0x3FE24F4BC9EA5E45.8),char #0x3A.1>.8, rax.8 ; 18000CC41 u=sp+570.8   d=rax.8
100. 4 cfshl  (%var_368.8 ^ #-0x3FE24F4BC9EA5E45.8), #0x3A.1, cf.1 ; 18000CC41 u=sp+570.8   d=cf.1
100. 5 und    of.1                    ; 18000CC41 u=           d=of.1
100. 6 mov    rax.8, %var_360.8       ; 18000CC45 u=rax.8      d=sp+578.8
100. 7 mov    #0x64.4, %var_8A8.4     ; 18000CCBA u=           d=sp+30.4
100. 8 goto   @3                      ; 18000CCC2 u=
100. 8
101. 0 ; 1WAY-BLOCK 101 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000CCC7 END=18000CD0A] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
101. 0 ; USE: sp+5B.1,sp+698.1,sp+6F8.8
101. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+708..718
101. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
101. 0 or     %var_1E0.8, (#0x1000000000.8*xdu.8(%var_87D.1)), %var_1D0.8 ; 18000CCD8 u=sp+5B.1,sp+6F8.8 d=sp+708.8
101. 1 xdu    (%var_240.1 & #0xF.1), rax.8 ; 18000CCE8 u=sp+698.1   d=rax.8
101. 2 cfadd  rax.8, &($p_InLoadOrderModuleList_5).8, cf.1 ; 18000CCF2 u=rax.8      d=cf.1
101. 3 ofadd  rax.8, &($p_InLoadOrderModuleList_5).8, of.1 ; 18000CCF2 u=rax.8      d=of.1
101. 4 setz   (rax.8+&($p_InLoadOrderModuleList_5).8), #0.8, zf.1 ; 18000CCF2 u=rax.8      d=zf.1
101. 5 setp   (rax.8+&($p_InLoadOrderModuleList_5).8), #0.8, pf.1 ; 18000CCF2 u=rax.8      d=pf.1
101. 6 sets   (rax.8+&($p_InLoadOrderModuleList_5).8), sf.1 ; 18000CCF2 u=rax.8      d=sf.1
101. 7 add    rax.8, &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000CCF2 u=rax.8      d=rcx.8
101. 8 add    rax.8, &($p_InLoadOrderModuleList_5).8, %var_1C8.8 ; 18000CCF5 u=rax.8      d=sp+710.8
101. 9 mov    #0xB3.4, %var_8A8.4     ; 18000CCFD u=           d=sp+30.4
101.10 goto   @3                      ; 18000CD05 u=
101.10
102. 0 ; 1WAY-BLOCK 102 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000CD0A END=18000CD7A] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
102. 0 ; USE: ds.2,sp+3D.1,(GLBLOW,sp+0..3D,sp+3E..,SHADOW,ARGS,GLBHIGH)
102. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+5E.1
102. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^1.7,rcx.8
102. 0 mov    &($p_InLoadOrderModuleList_8).8, rcx.8 ; 18000CD5B u=           d=rcx.8
102. 1 xdu    [ds.2:(xdu.8((xdu.4(%var_89B.1) >>l #4.1))+&($p_InLoadOrderModuleList_8).8)].1, rax.8 ; 18000CD62 u=ds.2,sp+3D.1,(GLBLOW,sp+0..3D,sp+3E..,SHADOW,ARGS,GLBHIGH) d=rax.8
102. 2 cfshl  al.1, #4.1, cf.1        ; 18000CD66 u=al.1       d=cf.1
102. 3 mul    #0x10.1, al.1, al.1     ; 18000CD66 u=al.1       d=al.1
102. 4 und    of.1                    ; 18000CD66 u=           d=of.1
102. 5 setz   al.1, #0.1, zf.1        ; 18000CD66 u=al.1       d=zf.1
102. 6 setp   al.1, #0.1, pf.1        ; 18000CD66 u=al.1       d=pf.1
102. 7 sets   al.1, sf.1              ; 18000CD66 u=al.1       d=sf.1
102. 8 mov    al.1, %var_87A.1        ; 18000CD69 u=al.1       d=sp+5E.1
102. 9 mov    #0xDD.4, %var_8A8.4     ; 18000CD6D u=           d=sp+30.4
102.10 goto   @3                      ; 18000CD75 u=
102.10
103. 0 ; 1WAY-BLOCK 103 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000CD7A END=18000CE68] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
103. 0 ; USE: sp+200.4,sp+208.8
103. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+210.4
103. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
103. 0 mov    #0.1, cf.1              ; 18000CE4D u=           d=cf.1
103. 1 mov    #0.1, of.1              ; 18000CE4D u=           d=of.1
103. 2 setz   (%var_6D8.4 ^ (#0x1B873593.4*(%var_6D0.4 | %var_6CC.4))), #0.4, zf.1 ; 18000CE4D u=sp+200.4,sp+208.8 d=zf.1
103. 3 setp   (%var_6D8.4 ^ (#0x1B873593.4*(%var_6D0.4 | %var_6CC.4))), #0.4, pf.1 ; 18000CE4D u=sp+200.4,sp+208.8 d=pf.1
103. 4 sets   (%var_6D8.4 ^ (#0x1B873593.4*(%var_6D0.4 | %var_6CC.4))), sf.1 ; 18000CE4D u=sp+200.4,sp+208.8 d=sf.1
103. 5 xdu    (%var_6D8.4 ^ (#0x1B873593.4*(%var_6D0.4 | %var_6CC.4))), rax.8 ; 18000CE4D u=sp+200.4,sp+208.8 d=rax.8
103. 6 xor    %var_6D8.4, (#0x1B873593.4*(%var_6D0.4 | %var_6CC.4)), %var_6C8.4 ; 18000CE54 u=sp+200.4,sp+208.8 d=sp+210.4
103. 7 mov    #0xD6.4, %var_8A8.4     ; 18000CE5B u=           d=sp+30.4
103. 8 goto   @3                      ; 18000CE63 u=
103. 8
104. 0 ; 1WAY-BLOCK 104 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000CE68 END=18000CF24] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
104. 0 ; USE: ds.2,sp+5A0.8,(GLBLOW,sp+0..5A0,sp+5A8..,SHADOW,ARGS,GLBHIGH)
104. 0 ; DEF: rax.8,sp+30.4,sp+5A8.8
104. 0 ; DNU: rax.8
104. 0 ldx    ds.2, (%var_338.8+#0x320.8), rax.8 ; 18000CE70 u=ds.2,sp+5A0.8,(GLBLOW,sp+0..5A0,sp+5A8..,SHADOW,ARGS,GLBHIGH) d=rax.8
104. 1 ldx    ds.2, (%var_338.8+#0x320.8), %var_330.8 ; 18000CE77 u=ds.2,sp+5A0.8,(GLBLOW,sp+0..5A0,sp+5A8..,SHADOW,ARGS,GLBHIGH) d=sp+5A8.8
104. 2 mov    #0x71.4, %var_8A8.4     ; 18000CF17 u=           d=sp+30.4
104. 3 goto   @3                      ; 18000CF1F u=
104. 3
105. 0 ; 1WAY-BLOCK 105 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000CF24 END=18000CF9F] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
105. 0 ; USE: sp+5C8.8,180281CB4.8
105. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+288.8
105. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
105. 0 xor    %var_310.8, $qword_180281CB4.8, rax.8 ; 18000CF6E u=sp+5C8.8,180281CB4.8 d=rax.8
105. 1 xor    ((%var_310.8 ^ $qword_180281CB4.8)+#0x4581C12A87917C75.8), #0xCA.8, rcx.8 ; 18000CF83 u=sp+5C8.8,180281CB4.8 d=rcx.8
105. 2 mov    #0.1, cf.1              ; 18000CF83 u=           d=cf.1
105. 3 mov    #0.1, of.1              ; 18000CF83 u=           d=of.1
105. 4 setz   (((%var_310.8 ^ $qword_180281CB4.8)+#0x4581C12A87917C75.8) ^ #0xCA.8), #0.8, zf.1 ; 18000CF83 u=sp+5C8.8,180281CB4.8 d=zf.1
105. 5 setp   (((%var_310.8 ^ $qword_180281CB4.8)+#0x4581C12A87917C75.8) ^ #0xCA.8), #0.8, pf.1 ; 18000CF83 u=sp+5C8.8,180281CB4.8 d=pf.1
105. 6 sets   ((%var_310.8 ^ $qword_180281CB4.8)+#0x4581C12A87917C75.8), sf.1 ; 18000CF83 u=sp+5C8.8,180281CB4.8 d=sf.1
105. 7 xor    ((%var_310.8 ^ $qword_180281CB4.8)+#0x4581C12A87917C75.8), #0xCA.8, %var_650.8 ; 18000CF8A u=sp+5C8.8,180281CB4.8 d=sp+288.8
105. 8 mov    #0x76.4, %var_8A8.4     ; 18000CF92 u=           d=sp+30.4
105. 9 goto   @3                      ; 18000CF9A u=
105. 9
106. 0 ; 1WAY-BLOCK 106 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000CF9F END=18000CFD6] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
106. 0 ; USE: ds.2,sp+D0.1,sp+848..858,(GLBLOW,sp+0..D0,sp+D1..848,sp+858..,SHADOW,ARGS,GLBHIGH)
106. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+3E.1,sp+858.8
106. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
106. 0 mov    #0.1, cf.1              ; 18000CFAD u=           d=cf.1
106. 1 mov    #0.1, of.1              ; 18000CFAD u=           d=of.1
106. 2 setz   (%var_90.8 | xdu.8((#0x100.4*xdu.4([ds.2:%var_88.8].1)))), #0.8, zf.1 ; 18000CFAD u=ds.2,sp+848..858,(GLBLOW,sp+0..848,sp+858..,SHADOW,ARGS,GLBHIGH) d=zf.1
106. 3 setp   (%var_90.8 | xdu.8((#0x100.4*xdu.4([ds.2:%var_88.8].1)))), #0.8, pf.1 ; 18000CFAD u=ds.2,sp+848..858,(GLBLOW,sp+0..848,sp+858..,SHADOW,ARGS,GLBHIGH) d=pf.1
106. 4 sets   (%var_90.8 | xdu.8((#0x100.4*xdu.4([ds.2:%var_88.8].1)))), sf.1 ; 18000CFAD u=ds.2,sp+848..858,(GLBLOW,sp+0..848,sp+858..,SHADOW,ARGS,GLBHIGH) d=sf.1
106. 5 or     %var_90.8, xdu.8((#0x100.4*xdu.4([ds.2:%var_88.8].1))), %var_80.8 ; 18000CFB5 u=ds.2,sp+848..858,(GLBLOW,sp+0..848,sp+858..,SHADOW,ARGS,GLBHIGH) d=sp+858.8
106. 6 xdu    %var_808.1, rax.8       ; 18000CFBD u=sp+D0.1    d=rax.8
106. 7 mov    %var_808.1, %var_89A.1  ; 18000CFC5 u=sp+D0.1    d=sp+3E.1
106. 8 mov    #0xE8.4, %var_8A8.4     ; 18000CFC9 u=           d=sp+30.4
106. 9 goto   @3                      ; 18000CFD1 u=
106. 9
107. 0 ; 1WAY-BLOCK 107 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000CFD6 END=18000D009] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
107. 0 ; USE: ds.2,sp+718..728,(GLBLOW,sp+0..718,sp+728..,SHADOW,ARGS,GLBHIGH)
107. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+728.8
107. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
107. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000CFDE u=           d=rcx.8
107. 1 or     %var_1C0.8, xdu.8((#0x10.4*xdu.4([ds.2:(%var_1B8.8+&($p_InLoadOrderModuleList_5).8)].1))), rax.8 ; 18000CFEC u=ds.2,sp+718..728,(GLBLOW,sp+0..718,sp+728..,SHADOW,ARGS,GLBHIGH) d=rax.8
107. 2 mov    #0.1, cf.1              ; 18000CFEC u=           d=cf.1
107. 3 mov    #0.1, of.1              ; 18000CFEC u=           d=of.1
107. 4 setz   (%var_1C0.8 | xdu.8((#0x10.4*xdu.4([ds.2:(%var_1B8.8+&($p_InLoadOrderModuleList_5).8)].1)))), #0.8, zf.1 ; 18000CFEC u=ds.2,sp+718..728,(GLBLOW,sp+0..718,sp+728..,SHADOW,ARGS,GLBHIGH) d=zf.1
107. 5 setp   (%var_1C0.8 | xdu.8((#0x10.4*xdu.4([ds.2:(%var_1B8.8+&($p_InLoadOrderModuleList_5).8)].1)))), #0.8, pf.1 ; 18000CFEC u=ds.2,sp+718..728,(GLBLOW,sp+0..718,sp+728..,SHADOW,ARGS,GLBHIGH) d=pf.1
107. 6 sets   (%var_1C0.8 | xdu.8((#0x10.4*xdu.4([ds.2:(%var_1B8.8+&($p_InLoadOrderModuleList_5).8)].1)))), sf.1 ; 18000CFEC u=ds.2,sp+718..728,(GLBLOW,sp+0..718,sp+728..,SHADOW,ARGS,GLBHIGH) d=sf.1
107. 7 or     %var_1C0.8, xdu.8((#0x10.4*xdu.4([ds.2:(%var_1B8.8+&($p_InLoadOrderModuleList_5).8)].1))), %var_1B0.8 ; 18000CFF4 u=ds.2,sp+718..728,(GLBLOW,sp+0..718,sp+728..,SHADOW,ARGS,GLBHIGH) d=sp+728.8
107. 8 mov    #0xB5.4, %var_8A8.4     ; 18000CFFC u=           d=sp+30.4
107. 9 goto   @3                      ; 18000D004 u=
107. 9
108. 0 ; 1WAY-BLOCK 108 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D009 END=18000D02A] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
108. 0 ; USE: sp+3F.1,180281C94.1
108. 0 ; DEF: rax.8,sp+30.4,sp+4E.2
108. 0 ; DNU: rax.8
108. 0 mov    %var_899.1, %var_88A.1  ; 18000D00E u=sp+3F.1    d=sp+4E.1
108. 1 xdu    $qword_180281C90@4.1, rax.8 ; 18000D012 u=180281C94.1 d=rax.8
108. 2 mov    $qword_180281C90@4.1, %var_889.1 ; 18000D019 u=180281C94.1 d=sp+4F.1
108. 3 mov    #0xD.4, %var_8A8.4      ; 18000D01D u=           d=sp+30.4
108. 4 goto   @3                      ; 18000D025 u=
108. 4
109. 0 ; 1WAY-BLOCK 109 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D02A END=18000D064] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
109. 0 ; USE: sp+5D.1,sp+E0.4,sp+7D8.8
109. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+7E0..7F0
109. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
109. 0 or     %var_100.8, xdu.8((#0x100000.4*xdu.4(%var_87B.1))), %var_F8.8 ; 18000D03A u=sp+5D.1,sp+7D8.8 d=sp+7E0.8
109. 1 mov    #0.1, cf.1              ; 18000D04C u=           d=cf.1
109. 2 mov    #0.1, of.1              ; 18000D04C u=           d=of.1
109. 3 setz   ((%var_7F8.4 >>l #8.1) & #0xF.4), #0.4, zf.1 ; 18000D04C u=sp+E0.4    d=zf.1
109. 4 setp   ((%var_7F8.4 >>l #8.1) & #0xF.4), #0.4, pf.1 ; 18000D04C u=sp+E0.4    d=pf.1
109. 5 mov    #0.1, sf.1              ; 18000D04C u=           d=sf.1
109. 6 xdu    ((%var_7F8.4 >>l #8.1) & #0xF.4), rax.8 ; 18000D04C u=sp+E0.4    d=rax.8
109. 7 xdu    ((%var_7F8.4 >>l #8.1) & #0xF.4), %var_F0.8 ; 18000D04F u=sp+E0.4    d=sp+7E8.8
109. 8 mov    #0xCC.4, %var_8A8.4     ; 18000D057 u=           d=sp+30.4
109. 9 goto   @3                      ; 18000D05F u=
109. 9
110. 0 ; 1WAY-BLOCK 110 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D064 END=18000D15C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
110. 0 ; USE: ds.2,sp+90.8,sp+860.8,(GLBLOW,sp+0..90,sp+98..860,sp+868..,SHADOW,ARGS,GLBHIGH)
110. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+868.8
110. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
110. 0 mov    &($loc_18022725F@1).8, rcx.8 ; 18000D130 u=           d=rcx.8
110. 1 or     %var_78.8, (#0x10000000.8*xdu.8([ds.2:((%var_848.8 >>l #0x1C.1)+&($loc_18022725F@1).8)].1)), rax.8 ; 18000D13F u=ds.2,sp+90.8,sp+860.8,(GLBLOW,sp+0..90,sp+98..860,sp+868..,SHADOW,ARGS,GLBHIGH) d=rax.8
110. 2 mov    #0.1, cf.1              ; 18000D13F u=           d=cf.1
110. 3 mov    #0.1, of.1              ; 18000D13F u=           d=of.1
110. 4 setz   (%var_78.8 | (#0x10000000.8*xdu.8([ds.2:((%var_848.8 >>l #0x1C.1)+&($loc_18022725F@1).8)].1))), #0.8, zf.1 ; 18000D13F u=ds.2,sp+90.8,sp+860.8,(GLBLOW,sp+0..90,sp+98..860,sp+868..,SHADOW,ARGS,GLBHIGH) d=zf.1
110. 5 setp   (%var_78.8 | (#0x10000000.8*xdu.8([ds.2:((%var_848.8 >>l #0x1C.1)+&($loc_18022725F@1).8)].1))), #0.8, pf.1 ; 18000D13F u=ds.2,sp+90.8,sp+860.8,(GLBLOW,sp+0..90,sp+98..860,sp+868..,SHADOW,ARGS,GLBHIGH) d=pf.1
110. 6 sets   (%var_78.8 | (#0x10000000.8*xdu.8([ds.2:((%var_848.8 >>l #0x1C.1)+&($loc_18022725F@1).8)].1))), sf.1 ; 18000D13F u=ds.2,sp+90.8,sp+860.8,(GLBLOW,sp+0..90,sp+98..860,sp+868..,SHADOW,ARGS,GLBHIGH) d=sf.1
110. 7 or     %var_78.8, (#0x10000000.8*xdu.8([ds.2:((%var_848.8 >>l #0x1C.1)+&($loc_18022725F@1).8)].1)), %var_70.8 ; 18000D147 u=ds.2,sp+90.8,sp+860.8,(GLBLOW,sp+0..90,sp+98..860,sp+868..,SHADOW,ARGS,GLBHIGH) d=sp+868.8
110. 8 mov    #0xEA.4, %var_8A8.4     ; 18000D14F u=           d=sp+30.4
110. 9 goto   @3                      ; 18000D157 u=
110. 9
111. 0 ; 1WAY-BLOCK 111 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D15C END=18000D182] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
111. 0 ; USE: sp+210.4
111. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+214.4
111. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
111. 0 mov    call !__ROL4__<fast:_DWORD %var_6C8.4,char #0xD.1>.4, eax.4 ; 18000D163 u=sp+210.4   d=eax.4
111. 1 mul    #5.4, eax.4, eax.4      ; 18000D166 split4 u=eax.4      d=eax.4
111. 2 cfadd  eax.4, #0xE6546B64.4, cf.1 ; 18000D169 u=eax.4      d=cf.1
111. 3 ofadd  #0xE6546B64.4, eax.4, of.1 ; 18000D169 u=eax.4      d=of.1
111. 4 setz   eax.4, #0x19AB949C.4, zf.1 ; 18000D169 u=eax.4      d=zf.1
111. 5 setp   eax.4, #0x19AB949C.4, pf.1 ; 18000D169 u=eax.4      d=pf.1
111. 6 sets   (eax.4-#0x19AB949C.4), sf.1 ; 18000D169 u=eax.4      d=sf.1
111. 7 xdu    (eax.4-#0x19AB949C.4), rax.8 ; 18000D169 u=eax.4      d=rax.8
111. 8 mov    eax.4, %var_6C4.4       ; 18000D16E u=eax.4      d=sp+214.4
111. 9 mov    #0xD7.4, %var_8A8.4     ; 18000D175 u=           d=sp+30.4
111.10 goto   @3                      ; 18000D17D u=
111.10
112. 0 ; 1WAY-BLOCK 112 INBOUNDS: 4 OUTBOUNDS: 113 [START=18000D182 END=18000D1AA] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
112. 0 ; USE: rsp.8,(rax.8,rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH)
112. 0 ; DEF: rdx.8,rcx.8,r8.8,r9.8,sp+A4.4,(cf.1,zf.1,sf.1,of.1,pf.1,rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..A4,sp+A8..,RET,SHADOW,ARGS,GLBHIGH)
112. 0 mov    #0x4CC74D88.4, %var_834.4 ; 18000D182 u=           d=sp+A4.4
112. 1 add    rsp.8, #0xA4.8, r9.8    ; 18000D18D u=rsp.8      d=r9.8
112. 2 mov    #0x33.8, rcx.8          ; 18000D195 u=           d=rcx.8
112. 3 mov    #0x3A.8, rdx.8          ; 18000D19A u=           d=rdx.8
112. 4 mov    #0x51.8, r8.8           ; 18000D19F u=           d=r8.8
112. 5 call   $sub_18013CC60          ; 18000D1A5 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
112. 5
113. 0 ; 1WAY-BLOCK 113 INBOUNDS: 112 OUTBOUNDS: 3 [START=18000D1AA END=18000D27C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
113. 0 ; USE: sp+A4.4
113. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+15C.4
113. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
113. 0 cfadd  %var_834.4, #0xBDA1FD6E.4, cf.1 ; 18000D1AF u=sp+A4.4    d=cf.1
113. 1 ofadd  %var_834.4, #0xBDA1FD6E.4, of.1 ; 18000D1AF u=sp+A4.4    d=of.1
113. 2 setz   %var_834.4, #0x425E0292.4, zf.1 ; 18000D1AF u=sp+A4.4    d=zf.1
113. 3 setp   %var_834.4, #0x425E0292.4, pf.1 ; 18000D1AF u=sp+A4.4    d=pf.1
113. 4 sets   (%var_834.4-#0x425E0292.4), sf.1 ; 18000D1AF u=sp+A4.4    d=sf.1
113. 5 xdu    (%var_834.4-#0x425E0292.4), rax.8 ; 18000D1AF u=sp+A4.4    d=rax.8
113. 6 sub    %var_834.4, #0x425E0292.4, %var_77C.4 ; 18000D1FA u=sp+A4.4    d=sp+15C.4
113. 7 mov    #0x48.4, %var_8A8.4     ; 18000D26F u=           d=sp+30.4
113. 8 goto   @3                      ; 18000D277 u=
113. 8
114. 0 ; 1WAY-BLOCK 114 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D27C END=18000D2AC] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
114. 0 ; USE: ds.2,sp+3C.1,sp+7B8.8,(GLBLOW,sp+0..3C,sp+3D..7B8,sp+7C0..,SHADOW,ARGS,GLBHIGH)
114. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+7C0.8
114. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
114. 0 mov    &($p_InLoadOrderModuleList_7).8, rcx.8 ; 18000D284 u=           d=rcx.8
114. 1 or     %var_120.8, xdu.8([ds.2:(xdu.8((%var_89C.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1), rax.8 ; 18000D28F u=ds.2,sp+3C.1,sp+7B8.8,(GLBLOW,sp+0..3C,sp+3D..7B8,sp+7C0..,SHADOW,ARGS,GLBHIGH) d=rax.8
114. 2 mov    #0.1, cf.1              ; 18000D28F u=           d=cf.1
114. 3 mov    #0.1, of.1              ; 18000D28F u=           d=of.1
114. 4 setz   (%var_120.8 | xdu.8([ds.2:(xdu.8((%var_89C.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1)), #0.8, zf.1 ; 18000D28F u=ds.2,sp+3C.1,sp+7B8.8,(GLBLOW,sp+0..3C,sp+3D..7B8,sp+7C0..,SHADOW,ARGS,GLBHIGH) d=zf.1
114. 5 setp   (%var_120.8 | xdu.8([ds.2:(xdu.8((%var_89C.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1)), #0.8, pf.1 ; 18000D28F u=ds.2,sp+3C.1,sp+7B8.8,(GLBLOW,sp+0..3C,sp+3D..7B8,sp+7C0..,SHADOW,ARGS,GLBHIGH) d=pf.1
114. 6 sets   (%var_120.8 | xdu.8([ds.2:(xdu.8((%var_89C.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1)), sf.1 ; 18000D28F u=ds.2,sp+3C.1,sp+7B8.8,(GLBLOW,sp+0..3C,sp+3D..7B8,sp+7C0..,SHADOW,ARGS,GLBHIGH) d=sf.1
114. 7 or     %var_120.8, xdu.8([ds.2:(xdu.8((%var_89C.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1), %var_118.8 ; 18000D297 u=ds.2,sp+3C.1,sp+7B8.8,(GLBLOW,sp+0..3C,sp+3D..7B8,sp+7C0..,SHADOW,ARGS,GLBHIGH) d=sp+7C0.8
114. 8 mov    #0xC8.4, %var_8A8.4     ; 18000D29F u=           d=sp+30.4
114. 9 goto   @3                      ; 18000D2A7 u=
114. 9
115. 0 ; 1WAY-BLOCK 115 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D2AC END=18000D2E4] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
115. 0 ; USE: r15.8,sp+178.1,sp+610.8
115. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,sp+30.4,sp+618.8
115. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
115. 0 xor    r15.8, %var_2C8.8, rax.8 ; 18000D2B4 u=r15.8,sp+610.8 d=rax.8
115. 1 sub    (r15.8 ^ %var_2C8.8), #0x1D77793ED61877F5.8, rdx.8 ; 18000D2C1 u=r15.8,sp+610.8 d=rdx.8
115. 2 xdu    %var_760.1, rcx.8       ; 18000D2C4 u=sp+178.1   d=rcx.8
115. 3 cfshr  rdx.8, %var_760.1, cf.1 ; 18000D2CC u=rdx.8,sp+178.1 d=cf.1
115. 4 shr    rdx.8, %var_760.1, rdx.8 ; 18000D2CC u=rdx.8,sp+178.1 d=rdx.8
115. 5 und    of.1                    ; 18000D2CC u=           d=of.1
115. 6 setz   rdx.8, #0.8, zf.1       ; 18000D2CC u=rdx.8      d=zf.1
115. 7 setp   rdx.8, #0.8, pf.1       ; 18000D2CC u=rdx.8      d=pf.1
115. 8 mov    #0.1, sf.1              ; 18000D2CC u=           d=sf.1
115. 9 mov    rdx.8, %var_2C0.8       ; 18000D2CF u=rdx.8      d=sp+618.8
115.10 mov    #0x83.4, %var_8A8.4     ; 18000D2D7 u=           d=sp+30.4
115.11 goto   @3                      ; 18000D2DF u=
115.11
116. 0 ; 1WAY-BLOCK 116 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D2E4 END=18000D390] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
116. 0 ; USE: sp+53.1,sp+144.8
116. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+14C.4,sp+358.8
116. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
116. 0 or     %var_794.4, (#0x100.4*%var_790.4), %var_78C.4 ; 18000D2F5 u=sp+144.8   d=sp+14C.4
116. 1 xdu    (xdu.4(%var_885.1) >>l #4.1), rax.8 ; 18000D36E u=sp+53.1    d=rax.8
116. 2 cfadd  rax.8, &($p_InLoadOrderModuleList_1).8, cf.1 ; 18000D378 u=rax.8      d=cf.1
116. 3 ofadd  rax.8, &($p_InLoadOrderModuleList_1).8, of.1 ; 18000D378 u=rax.8      d=of.1
116. 4 setz   (rax.8+&($p_InLoadOrderModuleList_1).8), #0.8, zf.1 ; 18000D378 u=rax.8      d=zf.1
116. 5 setp   (rax.8+&($p_InLoadOrderModuleList_1).8), #0.8, pf.1 ; 18000D378 u=rax.8      d=pf.1
116. 6 sets   (rax.8+&($p_InLoadOrderModuleList_1).8), sf.1 ; 18000D378 u=rax.8      d=sf.1
116. 7 add    rax.8, &($p_InLoadOrderModuleList_1).8, rcx.8 ; 18000D378 u=rax.8      d=rcx.8
116. 8 add    rax.8, &($p_InLoadOrderModuleList_1).8, %var_580.8 ; 18000D37B u=rax.8      d=sp+358.8
116. 9 mov    #0x2C.4, %var_8A8.4     ; 18000D383 u=           d=sp+30.4
116.10 goto   @3                      ; 18000D38B u=
116.10
117. 0 ; 1WAY-BLOCK 117 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D390 END=18000D421] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
117. 0 ; USE: sp+160.4
117. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+1E8.4
117. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
117. 0 setz   (%var_778.4 ^ #0xC82F00E4.4), #0.4, zf.1 ; 18000D404 u=sp+160.4   d=zf.1
117. 1 setp   (%var_778.4 ^ #0xC82F00E4.4), #0.4, pf.1 ; 18000D404 u=sp+160.4   d=pf.1
117. 2 sets   bnot(%var_778.4), sf.1  ; 18000D404 u=sp+160.4   d=sf.1
117. 3 mov    call !__ROL4__<fast:_DWORD (%var_778.4 ^ #0xC82F00E4.4),char #1.1>.4, eax.4 ; 18000D40B u=sp+160.4   d=eax.4
117. 4 cfshl  (%var_778.4 ^ #0xC82F00E4.4), #1.1, cf.1 ; 18000D40B u=sp+160.4   d=cf.1
117. 5 und    of.1                    ; 18000D40B u=           d=of.1
117. 6 xdu    eax.4, rax.8            ; 18000D40B u=eax.4      d=rax^4.4
117. 7 mov    eax.4, %var_6F0.4       ; 18000D40D u=eax.4      d=sp+1E8.4
117. 8 mov    #0xBE.4, %var_8A8.4     ; 18000D414 u=           d=sp+30.4
117. 9 goto   @3                      ; 18000D41C u=
117. 9
118. 0 ; 1WAY-BLOCK 118 INBOUNDS: 4 OUTBOUNDS: 119 [START=18000D421 END=18000D49D] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
118. 0 ; USE: rsp.8,(rax.8,rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH)
118. 0 ; DEF: rdx.8,rcx.8,r8.8,r9.8,(cf.1,zf.1,sf.1,of.1,pf.1,rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
118. 0 add    rsp.8, #0x288.8, r8.8   ; 18000D480 u=rsp.8      d=r8.8
118. 1 mov    #0x2B.8, rcx.8          ; 18000D488 u=           d=rcx.8
118. 2 mov    #0xF.8, rdx.8           ; 18000D48D u=           d=rdx.8
118. 3 mov    #0x63.8, r9.8           ; 18000D492 u=           d=r9.8
118. 4 call   $sub_18008CE30          ; 18000D498 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
118. 4
119. 0 ; 1WAY-BLOCK 119 INBOUNDS: 118 OUTBOUNDS: 3 [START=18000D49D END=18000D52D] MINREFS: STK=0/ARG=8E0, MAXBSP: 8
119. 0 ; USE: sp+290.8
119. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+38.4,sp+5D8.8
119. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
119. 0 mov    #-0x5B27C99487A6D83D.8, rcx.8 ; 18000D4A5 u=           d=rcx.8
119. 1 setz   (%var_648.8 ^ #-0x5B27C99487A6D83D.8), #0.8, zf.1 ; 18000D4AF u=sp+290.8   d=zf.1
119. 2 setp   (%var_648.8 ^ #-0x5B27C99487A6D83D.8), #0.8, pf.1 ; 18000D4AF u=sp+290.8   d=pf.1
119. 3 sets   bnot(%var_648.8), sf.1  ; 18000D4AF u=sp+290.8   d=sf.1
119. 4 mov    call !__ROL8__<fast:_QWORD (%var_648.8 ^ #-0x5B27C99487A6D83D.8),char #0x1E.1>.8, rax.8 ; 18000D514 u=sp+290.8   d=rax.8
119. 5 cfshl  (%var_648.8 ^ #-0x5B27C99487A6D83D.8), #0x1E.1, cf.1 ; 18000D514 u=sp+290.8   d=cf.1
119. 6 und    of.1                    ; 18000D514 u=           d=of.1
119. 7 mov    rax.8, %var_300.8       ; 18000D518 u=rax.8      d=sp+5D8.8
119. 8 mov    #0x77.4, %var_8A0.4     ; 18000D520 u=           d=sp+38.4
119. 9 goto   @3                      ; 18000D528 u=
119. 9
120. 0 ; 1WAY-BLOCK 120 INBOUNDS: 4 OUTBOUNDS: 121 [START=18000D52D END=18000D5B1] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
120. 0 ; USE: sp+1E4.4,sp+678.8,(rax.8,rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..1E4,sp+1E8..678,sp+680..,SHADOW,ARGS,GLBHIGH)
120. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rdx.8,rcx.8,r8.8,r9.8,sp+20.8,(rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..20,sp+28..,RET,SHADOW,ARGS,GLBHIGH)
120. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
120. 0 cfadd  %var_260.8, #0x10.8, cf.1 ; 18000D58C u=sp+678.8   d=cf.1
120. 1 ofadd  #0x10.8, %var_260.8, of.1 ; 18000D58C u=sp+678.8   d=of.1
120. 2 setz   (%var_260.8+#0x10.8), #0.8, zf.1 ; 18000D58C u=sp+678.8   d=zf.1
120. 3 setp   (%var_260.8+#0x10.8), #0.8, pf.1 ; 18000D58C u=sp+678.8   d=pf.1
120. 4 sets   (%var_260.8+#0x10.8), sf.1 ; 18000D58C u=sp+678.8   d=sf.1
120. 5 add    %var_260.8, #0x10.8, rcx.8 ; 18000D58C u=sp+678.8   d=rcx.8
120. 6 xdu    %var_6F4.4, r8.8        ; 18000D590 u=sp+1E4.4   d=r8.8
120. 7 mov    #0x5F.8, %var_8B8.8     ; 18000D598 u=           d=sp+20.8
120. 8 mov    #0x20.8, rdx.8          ; 18000D5A1 u=           d=rdx.8
120. 9 mov    #3.8, r9.8              ; 18000D5A6 u=           d=r9.8
120.10 call   $sub_180096B30          ; 18000D5AC u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
120.10
121. 0 ; 1WAY-BLOCK 121 INBOUNDS: 120 OUTBOUNDS: 3 [START=18000D5B1 END=18000D5BE] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
121. 0 ; DEF: sp+30.4
121. 0 mov    #0xA6.4, %var_8A8.4     ; 18000D5B1 u=           d=sp+30.4
121. 1 goto   @3                      ; 18000D5B9 u=
121. 1
122. 0 ; 1WAY-BLOCK 122 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D5BE END=18000D660] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
122. 0 ; USE: r14.8,ds.2,sp+878..888,(GLBLOW,sp+0..878,sp+888..,SHADOW,ARGS,GLBHIGH)
122. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+888.8
122. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
122. 0 mov    &($loc_18022725F@1).8, rcx.8 ; 18000D5C6 u=           d=rcx.8
122. 1 add    r14.8, (%var_60.8 | xdu.8((#0x10.4*xdu.4([ds.2:(%var_58.8+&($loc_18022725F@1).8)].1)))), rax.8 ; 18000D642 u=r14.8,ds.2,sp+878..888,(GLBLOW,sp+0..878,sp+888..,SHADOW,ARGS,GLBHIGH) d=rax.8
122. 2 cfadd  rax.8, #0x35993197.8, cf.1 ; 18000D645 u=rax.8      d=cf.1
122. 3 ofadd  #0x35993197.8, rax.8, of.1 ; 18000D645 u=rax.8      d=of.1
122. 4 setz   (rax.8+#0x35993197.8), #0.8, zf.1 ; 18000D645 u=rax.8      d=zf.1
122. 5 setp   (rax.8+#0x35993197.8), #0.8, pf.1 ; 18000D645 u=rax.8      d=pf.1
122. 6 sets   (rax.8+#0x35993197.8), sf.1 ; 18000D645 u=rax.8      d=sf.1
122. 7 add    rax.8, #0x35993197.8, rax.8 ; 18000D645 u=rax.8      d=rax.8
122. 8 mov    rax.8, %var_50.8        ; 18000D64B u=rax.8      d=sp+888.8
122. 9 mov    #0xED.4, %var_8A8.4     ; 18000D653 u=           d=sp+30.4
122.10 goto   @3                      ; 18000D65B u=
122.10
123. 0 ; 1WAY-BLOCK 123 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D660 END=18000D68B] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
123. 0 ; USE: sp+174.4
123. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+178.4
123. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
123. 0 mov    call !__ROL4__<fast:_DWORD %var_764.4,char #0xC.1>.4, eax.4 ; 18000D667 u=sp+174.4   d=eax.4
123. 1 mov    call !__ROL4__<fast:_DWORD (eax.4+#0x7F5FA08E.4),char #0xE.1>.4, eax.4 ; 18000D66F u=eax.4      d=eax.4
123. 2 xor    eax.4, #0x3EA1067F.4, eax.4 ; 18000D672 u=eax.4      d=eax.4
123. 3 mov    #0.1, cf.1              ; 18000D672 u=           d=cf.1
123. 4 mov    #0.1, of.1              ; 18000D672 u=           d=of.1
123. 5 setz   eax.4, #0.4, zf.1       ; 18000D672 u=eax.4      d=zf.1
123. 6 setp   eax.4, #0.4, pf.1       ; 18000D672 u=eax.4      d=pf.1
123. 7 sets   eax.4, sf.1             ; 18000D672 u=eax.4      d=sf.1
123. 8 xdu    eax.4, rax.8            ; 18000D672 u=eax.4      d=rax^4.4
123. 9 mov    eax.4, %var_760.4       ; 18000D677 u=eax.4      d=sp+178.4
123.10 mov    #0x7F.4, %var_8A8.4     ; 18000D67E u=           d=sp+30.4
123.11 goto   @3                      ; 18000D686 u=
123.11
124. 0 ; 1WAY-BLOCK 124 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D68B END=18000D708] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
124. 0 ; USE: 1802847D8.8
124. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+680.8
124. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
124. 0 xor    $n0x72.8, #0x72.8, rax.8 ; 18000D6EF u=1802847D8.8 d=rax.8
124. 1 mov    #0.1, cf.1              ; 18000D6EF u=           d=cf.1
124. 2 mov    #0.1, of.1              ; 18000D6EF u=           d=of.1
124. 3 setz   ($n0x72.8 ^ #0x72.8), #0.8, zf.1 ; 18000D6EF u=1802847D8.8 d=zf.1
124. 4 setp   ($n0x72.8 ^ #0x72.8), #0.8, pf.1 ; 18000D6EF u=1802847D8.8 d=pf.1
124. 5 sets   $n0x72.8, sf.1          ; 18000D6EF u=1802847D8.8 d=sf.1
124. 6 xor    $n0x72.8, #0x72.8, %var_258.8 ; 18000D6F3 u=1802847D8.8 d=sp+680.8
124. 7 mov    #0xA7.4, %var_8A8.4     ; 18000D6FB u=           d=sp+30.4
124. 8 goto   @3                      ; 18000D703 u=
124. 8
125. 0 ; 1WAY-BLOCK 125 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D708 END=18000D79A] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
125. 0 ; USE: ds.2,sp+CC.1,sp+7B0.8,(GLBLOW,sp+0..CC,sp+CD..7B0,sp+7B8..,SHADOW,ARGS,GLBHIGH)
125. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+3C.1,sp+7B8.8
125. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
125. 0 xdu    [ds.2:%var_128.8].1, rax.8 ; 18000D710 u=ds.2,sp+7B0.8,(GLBLOW,sp+0..7B0,sp+7B8..,SHADOW,ARGS,GLBHIGH) d=rax.8
125. 1 cfshl  rax.8, #0x1C.1, cf.1    ; 18000D713 u=rax.8      d=cf.1
125. 2 mul    #0x10000000.8, rax.8, rax.8 ; 18000D713 u=rax.8      d=rax.8
125. 3 und    of.1                    ; 18000D713 u=           d=of.1
125. 4 setz   rax.8, #0.8, zf.1       ; 18000D713 u=rax.8      d=zf.1
125. 5 setp   rax.8, #0.8, pf.1       ; 18000D713 u=rax.8      d=pf.1
125. 6 sets   rax.8, sf.1             ; 18000D713 u=rax.8      d=sf.1
125. 7 mov    rax.8, %var_120.8       ; 18000D717 u=rax.8      d=sp+7B8.8
125. 8 xdu    %var_80C.1, rax.8       ; 18000D71F u=sp+CC.1    d=rax.8
125. 9 mov    %var_80C.1, %var_89C.1  ; 18000D727 u=sp+CC.1    d=sp+3C.1
125.10 mov    #0xC7.4, %var_8A8.4     ; 18000D78D u=           d=sp+30.4
125.11 goto   @3                      ; 18000D795 u=
125.11
126. 0 ; 1WAY-BLOCK 126 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D79A END=18000D88F] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
126. 0 ; USE: sp+234.C
126. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+240.4
126. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
126. 0 mov    #0.1, cf.1              ; 18000D874 u=           d=cf.1
126. 1 mov    #0.1, of.1              ; 18000D874 u=           d=of.1
126. 2 setz   (%var_6A4.4 ^ (#0x1B873593.4*(%var_69C.4 | (%var_6A0.4 >>l #0x11.1)))), #0.4, zf.1 ; 18000D874 u=sp+234.C   d=zf.1
126. 3 setp   (%var_6A4.4 ^ (#0x1B873593.4*(%var_69C.4 | (%var_6A0.4 >>l #0x11.1)))), #0.4, pf.1 ; 18000D874 u=sp+234.C   d=pf.1
126. 4 sets   (%var_6A4.4 ^ (#0x1B873593.4*(%var_69C.4 | (%var_6A0.4 >>l #0x11.1)))), sf.1 ; 18000D874 u=sp+234.C   d=sf.1
126. 5 xdu    (%var_6A4.4 ^ (#0x1B873593.4*(%var_69C.4 | (%var_6A0.4 >>l #0x11.1)))), rax.8 ; 18000D874 u=sp+234.C   d=rax.8
126. 6 xor    %var_6A4.4, (#0x1B873593.4*(%var_69C.4 | (%var_6A0.4 >>l #0x11.1))), %var_698.4 ; 18000D87B u=sp+234.C   d=sp+240.4
126. 7 mov    #0xF4.4, %var_8A8.4     ; 18000D882 u=           d=sp+30.4
126. 8 goto   @3                      ; 18000D88A u=
126. 8
127. 0 ; 1WAY-BLOCK 127 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D88F END=18000D8BA] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
127. 0 ; USE: r14d.4,ds.2,sp+2D0.8,sp+808.4,(GLBLOW,sp+0..2D0,sp+2D8..808,sp+80C..,SHADOW,ARGS,GLBHIGH)
127. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+2D8.8
127. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
127. 0 cfadd  r14d.4, %var_D0.4, cf.1 ; 18000D896 u=r14d.4,sp+808.4 d=cf.1
127. 1 ofadd  r14d.4, %var_D0.4, of.1 ; 18000D896 u=r14d.4,sp+808.4 d=of.1
127. 2 setz   (r14d.4+%var_D0.4), #0.4, zf.1 ; 18000D896 u=r14d.4,sp+808.4 d=zf.1
127. 3 setp   (r14d.4+%var_D0.4), #0.4, pf.1 ; 18000D896 u=r14d.4,sp+808.4 d=pf.1
127. 4 sets   (r14d.4+%var_D0.4), sf.1 ; 18000D896 u=r14d.4,sp+808.4 d=sf.1
127. 5 mov    %var_608.8, rcx.8       ; 18000D899 u=sp+2D0.8   d=rcx.8
127. 6 ldx    ds.2, (%var_608.8+xdu.8((r14d.4+%var_D0.4))), rax.8 ; 18000D8A1 u=r14d.4,ds.2,sp+2D0.8,sp+808.4,(GLBLOW,sp+0..2D0,sp+2D8..808,sp+80C..,SHADOW,ARGS,GLBHIGH) d=rax.8
127. 7 ldx    ds.2, (%var_608.8+xdu.8((r14d.4+%var_D0.4))), %var_600.8 ; 18000D8A5 u=r14d.4,ds.2,sp+2D0.8,sp+808.4,(GLBLOW,sp+0..2D0,sp+2D8..808,sp+80C..,SHADOW,ARGS,GLBHIGH) d=sp+2D8.8
127. 8 mov    #0xD0.4, %var_8A8.4     ; 18000D8AD u=           d=sp+30.4
127. 9 goto   @3                      ; 18000D8B5 u=
127. 9
128. 0 ; 1WAY-BLOCK 128 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D8BA END=18000D95C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
128. 0 ; USE: sp+16C.4,180281E5D.4
128. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+170.4
128. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
128. 0 xor    (%var_76C.4 ^ $dword_180281E5D.4), #0x6B035F3E.4, eax.4 ; 18000D93E u=sp+16C.4,180281E5D.4 d=eax.4
128. 1 cfadd  eax.4, #0xB33F8E20.4, cf.1 ; 18000D943 u=eax.4      d=cf.1
128. 2 ofadd  #0xB33F8E20.4, eax.4, of.1 ; 18000D943 u=eax.4      d=of.1
128. 3 setz   eax.4, #0x4CC071E0.4, zf.1 ; 18000D943 u=eax.4      d=zf.1
128. 4 setp   eax.4, #0x4CC071E0.4, pf.1 ; 18000D943 u=eax.4      d=pf.1
128. 5 sets   (eax.4-#0x4CC071E0.4), sf.1 ; 18000D943 u=eax.4      d=sf.1
128. 6 xdu    (eax.4-#0x4CC071E0.4), rax.8 ; 18000D943 u=eax.4      d=rax.8
128. 7 mov    eax.4, %var_768.4       ; 18000D948 u=eax.4      d=sp+170.4
128. 8 mov    #0x79.4, %var_8A8.4     ; 18000D94F u=           d=sp+30.4
128. 9 goto   @3                      ; 18000D957 u=
128. 9
129. 0 ; 1WAY-BLOCK 129 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D95C END=18000D993] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
129. 0 ; USE: ds.2,sp+768..778,180281B27.8,(GLBLOW,sp+0..768,sp+778..,SHADOW,ARGS,100AE0..180281B27,180281B2F..)
129. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+778.8
129. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
129. 0 mov    call !__ROL8__<fast:_QWORD (%var_170.8 | (#0x1000000000000000.8*xdu.8([ds.2:%var_168.8].1))),char #0x3D.1>.8, rax.8 ; 18000D973 u=ds.2,sp+768..778,(GLBLOW,sp+0..768,sp+778..,SHADOW,ARGS,GLBHIGH) d=rax.8
129. 1 xor    $qword_180281B27.8, rax.8, rax.8 ; 18000D977 u=rax.8,180281B27.8 d=rax.8
129. 2 mov    #0.1, cf.1              ; 18000D977 u=           d=cf.1
129. 3 mov    #0.1, of.1              ; 18000D977 u=           d=of.1
129. 4 setz   rax.8, #0.8, zf.1       ; 18000D977 u=rax.8      d=zf.1
129. 5 setp   rax.8, #0.8, pf.1       ; 18000D977 u=rax.8      d=pf.1
129. 6 sets   rax.8, sf.1             ; 18000D977 u=rax.8      d=sf.1
129. 7 mov    rax.8, %var_160.8       ; 18000D97E u=rax.8      d=sp+778.8
129. 8 mov    #0xBC.4, %var_8A8.4     ; 18000D986 u=           d=sp+30.4
129. 9 goto   @3                      ; 18000D98E u=
129. 9
130. 0 ; 1WAY-BLOCK 130 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000D993 END=18000DA0C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
130. 0 ; USE: ds.2,sp+6E8.1,(GLBLOW,sp+0..6E8,sp+6E9..,SHADOW,ARGS,GLBHIGH)
130. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+748.8
130. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
130. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000D99E u=           d=rcx.8
130. 1 xdu    [ds.2:(xdu.8((%var_1F0.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1, eax.4 ; 18000D9A5 u=ds.2,sp+6E8.1,(GLBLOW,sp+0..6E8,sp+6E9..,SHADOW,ARGS,GLBHIGH) d=eax.4
130. 2 cfshl  eax.4, #8.1, cf.1       ; 18000D9A9 u=eax.4      d=cf.1
130. 3 mul    #0x100.4, eax.4, eax.4  ; 18000D9A9 u=eax.4      d=eax.4
130. 4 und    of.1                    ; 18000D9A9 u=           d=of.1
130. 5 setz   eax.4, #0.4, zf.1       ; 18000D9A9 u=eax.4      d=zf.1
130. 6 setp   eax.4, #0.4, pf.1       ; 18000D9A9 u=eax.4      d=pf.1
130. 7 sets   eax.4, sf.1             ; 18000D9A9 u=eax.4      d=sf.1
130. 8 xdu    eax.4, rax.8            ; 18000D9A9 u=eax.4      d=rax^4.4
130. 9 xdu    eax.4, %var_190.8       ; 18000D9AC u=eax.4      d=sp+748.8
130.10 mov    #0xB8.4, %var_8A8.4     ; 18000D9FF u=           d=sp+30.4
130.11 goto   @3                      ; 18000DA07 u=
130.11
131. 0 ; 1WAY-BLOCK 131 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000DA0C END=18000DB21] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
131. 0 ; USE: sp+3E.1,sp+868..878
131. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+878..888
131. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
131. 0 or     %var_68.8, %var_70.8, %var_60.8 ; 18000DA6E u=sp+868..878 d=sp+878.8
131. 1 cfshr  xdu.4(%var_89A.1), #4.1, cf.1 ; 18000DAB7 u=sp+3E.1    d=cf.1
131. 2 und    of.1                    ; 18000DAB7 u=           d=of.1
131. 3 setz   (xdu.4(%var_89A.1) >>l #4.1), #0.4, zf.1 ; 18000DAB7 u=sp+3E.1    d=zf.1
131. 4 setp   (xdu.4(%var_89A.1) >>l #4.1), #0.4, pf.1 ; 18000DAB7 u=sp+3E.1    d=pf.1
131. 5 mov    #0.1, sf.1              ; 18000DAB7 u=           d=sf.1
131. 6 xdu    (xdu.4(%var_89A.1) >>l #4.1), rax.8 ; 18000DAB7 u=sp+3E.1    d=rax.8
131. 7 xdu    (xdu.4(%var_89A.1) >>l #4.1), %var_58.8 ; 18000DABA u=sp+3E.1    d=sp+880.8
131. 8 mov    #0xEC.4, %var_8A8.4     ; 18000DB14 u=           d=sp+30.4
131. 9 goto   @3                      ; 18000DB1C u=
131. 9
132. 0 ; 1WAY-BLOCK 132 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000DB21 END=18000DB58] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
132. 0 ; USE: ds.2,sp+370.1,sp+400.8,(GLBLOW,sp+0..370,sp+371..400,sp+408..,SHADOW,ARGS,GLBHIGH)
132. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+408.8
132. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
132. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000DB2C u=           d=rcx.8
132. 1 or     %var_4D8.8, (#0x1000000000000.8*xdu.8([ds.2:(xdu.8((%var_568.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)), rax.8 ; 18000DB3B u=ds.2,sp+370.1,sp+400.8,(GLBLOW,sp+0..370,sp+371..400,sp+408..,SHADOW,ARGS,GLBHIGH) d=rax.8
132. 2 mov    #0.1, cf.1              ; 18000DB3B u=           d=cf.1
132. 3 mov    #0.1, of.1              ; 18000DB3B u=           d=of.1
132. 4 setz   (%var_4D8.8 | (#0x1000000000000.8*xdu.8([ds.2:(xdu.8((%var_568.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, zf.1 ; 18000DB3B u=ds.2,sp+370.1,sp+400.8,(GLBLOW,sp+0..370,sp+371..400,sp+408..,SHADOW,ARGS,GLBHIGH) d=zf.1
132. 5 setp   (%var_4D8.8 | (#0x1000000000000.8*xdu.8([ds.2:(xdu.8((%var_568.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, pf.1 ; 18000DB3B u=ds.2,sp+370.1,sp+400.8,(GLBLOW,sp+0..370,sp+371..400,sp+408..,SHADOW,ARGS,GLBHIGH) d=pf.1
132. 6 sets   (%var_4D8.8 | (#0x1000000000000.8*xdu.8([ds.2:(xdu.8((%var_568.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), sf.1 ; 18000DB3B u=ds.2,sp+370.1,sp+400.8,(GLBLOW,sp+0..370,sp+371..400,sp+408..,SHADOW,ARGS,GLBHIGH) d=sf.1
132. 7 or     %var_4D8.8, (#0x1000000000000.8*xdu.8([ds.2:(xdu.8((%var_568.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)), %var_4D0.8 ; 18000DB43 u=ds.2,sp+370.1,sp+400.8,(GLBLOW,sp+0..370,sp+371..400,sp+408..,SHADOW,ARGS,GLBHIGH) d=sp+408.8
132. 8 mov    #0x3F.4, %var_8A8.4     ; 18000DB4B u=           d=sp+30.4
132. 9 goto   @3                      ; 18000DB53 u=
132. 9
133. 0 ; 1WAY-BLOCK 133 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000DB58 END=18000DB65] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
133. 0 ; DEF: sp+30.4
133. 0 mov    #0xEF.4, %var_8A8.4     ; 18000DB58 u=           d=sp+30.4
133. 1 goto   @3                      ; 18000DB60 u=
133. 1
134. 0 ; 1WAY-BLOCK 134 INBOUNDS: 4 OUTBOUNDS: 135 [START=18000DB65 END=18000DBD2] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
134. 0 ; USE: (rax.8,rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH)
134. 0 ; DEF: rdx.8,rcx.8,r8.8,r9.8,(cf.1,zf.1,sf.1,of.1,pf.1,rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
134. 0 mov    #0x59.8, rcx.8          ; 18000DBB7 u=           d=rcx.8
134. 1 mov    #0x1B.8, rdx.8          ; 18000DBBC u=           d=rdx.8
134. 2 mov    #7.8, r8.8              ; 18000DBC1 u=           d=r8.8
134. 3 mov    #0xEA60.8, r9.8         ; 18000DBC7 u=           d=r9.8
134. 4 call   $sub_180207670          ; 18000DBCD u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
134. 4
135. 0 ; 1WAY-BLOCK 135 INBOUNDS: 134 OUTBOUNDS: 136 [START=18000DBD2 END=18000DBEA] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
135. 0 ; USE: rax.8,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH)
135. 0 ; DEF: rdx.8,rcx.8,r8.8,r9.8,(cf.1,zf.1,sf.1,of.1,pf.1,rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
135. 0 mov    #0x53.8, rcx.8          ; 18000DBD2 u=           d=rcx.8
135. 1 mov    #0x10.8, rdx.8          ; 18000DBD7 u=           d=rdx.8
135. 2 mov    #0x1E.8, r9.8           ; 18000DBDC u=           d=r9.8
135. 3 mov    rax.8, r8.8             ; 18000DBE2 u=rax.8      d=r8.8
135. 4 call   $sub_1800E0770          ; 18000DBE5 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
135. 4
136. 0 ; 1WAY-BLOCK 136 INBOUNDS: 135 OUTBOUNDS: 3 [START=18000DBEA END=18000DBF7] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
136. 0 ; DEF: sp+30.4
136. 0 mov    #1.4, %var_8A8.4        ; 18000DBEA u=           d=sp+30.4
136. 1 goto   @3                      ; 18000DBF2 u=
136. 1
137. 0 ; 1WAY-BLOCK 137 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000DBF7 END=18000DCAF] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
137. 0 ; USE: ds.2,sp+128.4,sp+328.8,(GLBLOW,sp+0..128,sp+12C..328,sp+330..,SHADOW,ARGS,GLBHIGH)
137. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+12C.4
137. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
137. 0 mov    #0.1, cf.1              ; 18000DC4F u=           d=cf.1
137. 1 mov    #0.1, of.1              ; 18000DC4F u=           d=of.1
137. 2 setz   (%var_7B0.4 | (#0x100.4*xdu.4([ds.2:%var_5B0.8].1))), #0.4, zf.1 ; 18000DC4F u=ds.2,sp+128.4,sp+328.8,(GLBLOW,sp+0..128,sp+12C..328,sp+330..,SHADOW,ARGS,GLBHIGH) d=zf.1
137. 3 setp   (%var_7B0.4 | (#0x100.4*xdu.4([ds.2:%var_5B0.8].1))), #0.4, pf.1 ; 18000DC4F u=ds.2,sp+128.4,sp+328.8,(GLBLOW,sp+0..128,sp+12C..328,sp+330..,SHADOW,ARGS,GLBHIGH) d=pf.1
137. 4 sets   (%var_7B0.4 | (#0x100.4*xdu.4([ds.2:%var_5B0.8].1))), sf.1 ; 18000DC4F u=ds.2,sp+128.4,sp+328.8,(GLBLOW,sp+0..128,sp+12C..328,sp+330..,SHADOW,ARGS,GLBHIGH) d=sf.1
137. 5 xdu    (%var_7B0.4 | (#0x100.4*xdu.4([ds.2:%var_5B0.8].1))), rax.8 ; 18000DC4F u=ds.2,sp+128.4,sp+328.8,(GLBLOW,sp+0..128,sp+12C..328,sp+330..,SHADOW,ARGS,GLBHIGH) d=rax.8
137. 6 or     %var_7B0.4, (#0x100.4*xdu.4([ds.2:%var_5B0.8].1)), %var_7AC.4 ; 18000DC56 u=ds.2,sp+128.4,sp+328.8,(GLBLOW,sp+0..128,sp+12C..328,sp+330..,SHADOW,ARGS,GLBHIGH) d=sp+12C.4
137. 7 mov    #0x20.4, %var_8A8.4     ; 18000DCA2 u=           d=sp+30.4
137. 8 goto   @3                      ; 18000DCAA u=
137. 8
138. 0 ; 1WAY-BLOCK 138 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000DCAF END=18000DCC5] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
138. 0 ; USE: sp+5F.1
138. 0 ; DEF: rax.8,sp+30.4,sp+3F.1
138. 0 ; DNU: rax.8
138. 0 xdu    %var_879.1, rax.8       ; 18000DCAF u=sp+5F.1    d=rax.8
138. 1 mov    %var_879.1, %var_899.1  ; 18000DCB4 u=sp+5F.1    d=sp+3F.1
138. 2 mov    #0xC.4, %var_8A8.4      ; 18000DCB8 u=           d=sp+30.4
138. 3 goto   @3                      ; 18000DCC0 u=
138. 3
139. 0 ; 1WAY-BLOCK 139 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000DCC5 END=18000DD75] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
139. 0 ; USE: sp+40.8,sp+54.1
139. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+378..390
139. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
139. 0 mul    #0x10000000000000.8, xdu.8(%var_884.1), %var_560.8 ; 18000DCCE u=sp+54.1    d=sp+378.8
139. 1 shr    %var_898.8, #0x18.1, %var_558.8 ; 18000DD51 u=sp+40.8    d=sp+380.8
139. 2 cfshr  %var_898.4, #0x1C.1, cf.1 ; 18000DD5D u=sp+40.4    d=cf.1
139. 3 und    of.1                    ; 18000DD5D u=           d=of.1
139. 4 setz   (%var_898.4 >>l #0x1C.1), #0.4, zf.1 ; 18000DD5D u=sp+40.4    d=zf.1
139. 5 setp   (%var_898.4 >>l #0x1C.1), #0.4, pf.1 ; 18000DD5D u=sp+40.4    d=pf.1
139. 6 mov    #0.1, sf.1              ; 18000DD5D u=           d=sf.1
139. 7 xdu    (%var_898.4 >>l #0x1C.1), rax.8 ; 18000DD5D u=sp+40.4    d=rax.8
139. 8 xdu    (%var_898.4 >>l #0x1C.1), %var_550.8 ; 18000DD60 u=sp+40.4    d=sp+388.8
139. 9 mov    #0x33.4, %var_8A8.4     ; 18000DD68 u=           d=sp+30.4
139.10 goto   @3                      ; 18000DD70 u=
139.10
140. 0 ; 1WAY-BLOCK 140 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000DD75 END=18000DDFA] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
140. 0 ; USE: ds.2,sp+798.8,(GLBLOW,sp+0..798,sp+7A0..,SHADOW,ARGS,GLBHIGH)
140. 0 ; DEF: rax.8,sp+30.4,sp+220.4
140. 0 ; DNU: rax.8
140. 0 xdu    [ds.2:([ds.2:%var_140.8].8+#0x44.8)].4, rax.8 ; 18000DDE3 u=ds.2,sp+798.8,(GLBLOW,sp+0..798,sp+7A0..,SHADOW,ARGS,GLBHIGH) d=rax.8
140. 1 ldx    ds.2, ([ds.2:%var_140.8].8+#0x44.8), %var_6B8.4 ; 18000DDE6 u=ds.2,sp+798.8,(GLBLOW,sp+0..798,sp+7A0..,SHADOW,ARGS,GLBHIGH) d=sp+220.4
140. 2 mov    #0xE0.4, %var_8A8.4     ; 18000DDED u=           d=sp+30.4
140. 3 goto   @3                      ; 18000DDF5 u=
140. 3
141. 0 ; 1WAY-BLOCK 141 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000DDFA END=18000DE76] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
141. 0 ; USE: sp+244.4
141. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+248.4
141. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
141. 0 xdu    %var_694.4, rax.8       ; 18000DE51 u=sp+244.4   d=rax.8
141. 1 mov    #0.1, cf.1              ; 18000DE5F u=           d=cf.1
141. 2 mov    #0.1, of.1              ; 18000DE5F u=           d=of.1
141. 3 setz   ((%var_694.4 ^ (%var_694.4 >>l #0x10.1)) ^ #8.4), #0.4, zf.1 ; 18000DE5F u=sp+244.4   d=zf.1
141. 4 setp   ((%var_694.4 ^ (%var_694.4 >>l #0x10.1)) ^ #8.4), #0.4, pf.1 ; 18000DE5F u=sp+244.4   d=pf.1
141. 5 sets   (%var_694.4 ^ (%var_694.4 >>l #0x10.1)), sf.1 ; 18000DE5F u=sp+244.4   d=sf.1
141. 6 xdu    ((%var_694.4 ^ (%var_694.4 >>l #0x10.1)) ^ #8.4), rcx.8 ; 18000DE5F u=sp+244.4   d=rcx.8
141. 7 xor    (%var_694.4 ^ (%var_694.4 >>l #0x10.1)), #8.4, %var_690.4 ; 18000DE62 u=sp+244.4   d=sp+248.4
141. 8 mov    #0xF6.4, %var_8A8.4     ; 18000DE69 u=           d=sp+30.4
141. 9 goto   @3                      ; 18000DE71 u=
141. 9
142. 0 ; 1WAY-BLOCK 142 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000DE76 END=18000DEF5] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
142. 0 ; USE: ds.2,sp+540..550,(GLBLOW,sp+0..540,sp+550..,SHADOW,ARGS,GLBHIGH)
142. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+550.8
142. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
142. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000DEC9 u=           d=rcx.8
142. 1 or     %var_398.8, (#0x10000000000.8*xdu.8([ds.2:(%var_390.8+&($p_InLoadOrderModuleList_5).8)].1)), rax.8 ; 18000DED8 u=ds.2,sp+540..550,(GLBLOW,sp+0..540,sp+550..,SHADOW,ARGS,GLBHIGH) d=rax.8
142. 2 mov    #0.1, cf.1              ; 18000DED8 u=           d=cf.1
142. 3 mov    #0.1, of.1              ; 18000DED8 u=           d=of.1
142. 4 setz   (%var_398.8 | (#0x10000000000.8*xdu.8([ds.2:(%var_390.8+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, zf.1 ; 18000DED8 u=ds.2,sp+540..550,(GLBLOW,sp+0..540,sp+550..,SHADOW,ARGS,GLBHIGH) d=zf.1
142. 5 setp   (%var_398.8 | (#0x10000000000.8*xdu.8([ds.2:(%var_390.8+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, pf.1 ; 18000DED8 u=ds.2,sp+540..550,(GLBLOW,sp+0..540,sp+550..,SHADOW,ARGS,GLBHIGH) d=pf.1
142. 6 sets   (%var_398.8 | (#0x10000000000.8*xdu.8([ds.2:(%var_390.8+&($p_InLoadOrderModuleList_5).8)].1))), sf.1 ; 18000DED8 u=ds.2,sp+540..550,(GLBLOW,sp+0..540,sp+550..,SHADOW,ARGS,GLBHIGH) d=sf.1
142. 7 or     %var_398.8, (#0x10000000000.8*xdu.8([ds.2:(%var_390.8+&($p_InLoadOrderModuleList_5).8)].1)), %var_388.8 ; 18000DEE0 u=ds.2,sp+540..550,(GLBLOW,sp+0..540,sp+550..,SHADOW,ARGS,GLBHIGH) d=sp+550.8
142. 8 mov    #0x5F.4, %var_8A8.4     ; 18000DEE8 u=           d=sp+30.4
142. 9 goto   @3                      ; 18000DEF0 u=
142. 9
143. 0 ; 1WAY-BLOCK 143 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000DEF5 END=18000DF6E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
143. 0 ; USE: r12.8,sp+560.8,180281B27.8
143. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+568.8
143. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
143. 0 mov    call !__ROL8__<fast:_QWORD %var_378.8,char #0x3D.1>.8, rax.8 ; 18000DEFD u=sp+560.8   d=rax.8
143. 1 xor    r12.8, ($qword_180281B27.8 ^ rax.8), rax.8 ; 18000DF56 u=rax.8,r12.8,180281B27.8 d=rax.8
143. 2 mov    #0.1, cf.1              ; 18000DF56 u=           d=cf.1
143. 3 mov    #0.1, of.1              ; 18000DF56 u=           d=of.1
143. 4 setz   rax.8, #0.8, zf.1       ; 18000DF56 u=rax.8      d=zf.1
143. 5 setp   rax.8, #0.8, pf.1       ; 18000DF56 u=rax.8      d=pf.1
143. 6 sets   rax.8, sf.1             ; 18000DF56 u=rax.8      d=sf.1
143. 7 mov    rax.8, %var_370.8       ; 18000DF59 u=rax.8      d=sp+568.8
143. 8 mov    #0x62.4, %var_8A8.4     ; 18000DF61 u=           d=sp+30.4
143. 9 goto   @3                      ; 18000DF69 u=
143. 9
144. 0 ; 1WAY-BLOCK 144 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000DF6E END=18000DF9E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
144. 0 ; USE: ds.2,sp+3E.1,sp+858.8,(GLBLOW,sp+0..3E,sp+3F..858,sp+860..,SHADOW,ARGS,GLBHIGH)
144. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+860.8
144. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
144. 0 mov    &($loc_18022725F@1).8, rcx.8 ; 18000DF76 u=           d=rcx.8
144. 1 or     %var_80.8, xdu.8([ds.2:(xdu.8((%var_89A.1 & #0xF.1))+&($loc_18022725F@1).8)].1), rax.8 ; 18000DF81 u=ds.2,sp+3E.1,sp+858.8,(GLBLOW,sp+0..3E,sp+3F..858,sp+860..,SHADOW,ARGS,GLBHIGH) d=rax.8
144. 2 mov    #0.1, cf.1              ; 18000DF81 u=           d=cf.1
144. 3 mov    #0.1, of.1              ; 18000DF81 u=           d=of.1
144. 4 setz   (%var_80.8 | xdu.8([ds.2:(xdu.8((%var_89A.1 & #0xF.1))+&($loc_18022725F@1).8)].1)), #0.8, zf.1 ; 18000DF81 u=ds.2,sp+3E.1,sp+858.8,(GLBLOW,sp+0..3E,sp+3F..858,sp+860..,SHADOW,ARGS,GLBHIGH) d=zf.1
144. 5 setp   (%var_80.8 | xdu.8([ds.2:(xdu.8((%var_89A.1 & #0xF.1))+&($loc_18022725F@1).8)].1)), #0.8, pf.1 ; 18000DF81 u=ds.2,sp+3E.1,sp+858.8,(GLBLOW,sp+0..3E,sp+3F..858,sp+860..,SHADOW,ARGS,GLBHIGH) d=pf.1
144. 6 sets   (%var_80.8 | xdu.8([ds.2:(xdu.8((%var_89A.1 & #0xF.1))+&($loc_18022725F@1).8)].1)), sf.1 ; 18000DF81 u=ds.2,sp+3E.1,sp+858.8,(GLBLOW,sp+0..3E,sp+3F..858,sp+860..,SHADOW,ARGS,GLBHIGH) d=sf.1
144. 7 or     %var_80.8, xdu.8([ds.2:(xdu.8((%var_89A.1 & #0xF.1))+&($loc_18022725F@1).8)].1), %var_78.8 ; 18000DF89 u=ds.2,sp+3E.1,sp+858.8,(GLBLOW,sp+0..3E,sp+3F..858,sp+860..,SHADOW,ARGS,GLBHIGH) d=sp+860.8
144. 8 mov    #0xE9.4, %var_8A8.4     ; 18000DF91 u=           d=sp+30.4
144. 9 goto   @3                      ; 18000DF99 u=
144. 9
145. 0 ; 1WAY-BLOCK 145 INBOUNDS: 4 OUTBOUNDS: 146 [START=18000DF9E END=18000DFBC] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
145. 0 ; USE: rsp.8,(rax.8,rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH)
145. 0 ; DEF: rdx.8,rcx.8,r8.8,r9.8,(cf.1,zf.1,sf.1,of.1,pf.1,rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
145. 0 add    rsp.8, #0xA0.8, rcx.8   ; 18000DF9E u=rsp.8      d=rcx.8
145. 1 mov    #0x44.8, rdx.8          ; 18000DFA6 u=           d=rdx.8
145. 2 mov    #0x17.8, r8.8           ; 18000DFAB u=           d=r8.8
145. 3 mov    #0x50.8, r9.8           ; 18000DFB1 u=           d=r9.8
145. 4 call   $sub_1801865F0          ; 18000DFB7 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
145. 4
146. 0 ; 1WAY-BLOCK 146 INBOUNDS: 145 OUTBOUNDS: 3 [START=18000DFBC END=18000E04C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
146. 0 ; USE: sp+A0.4,sp+5D8.8
146. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+5E0.8
146. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
146. 0 mul    %var_300.8, xdu.8(%var_838.4), rax.8 ; 18000DFC3 u=sp+A0.4,sp+5D8.8 d=rax.8
146. 1 setnz  high.8((xds.16(%var_300.8)*xdu.16(%var_838.4))), #0.8, cf.1 ; 18000DFC3 u=sp+A0.4,sp+5D8.8 d=cf.1
146. 2 setnz  high.8((xds.16(%var_300.8)*xdu.16(%var_838.4))), #0.8, of.1 ; 18000DFC3 u=sp+A0.4,sp+5D8.8 d=of.1
146. 3 und    zf.1                    ; 18000DFC3 u=           d=zf.1
146. 4 und    sf.1                    ; 18000DFC3 u=           d=sf.1
146. 5 und    pf.1                    ; 18000DFC3 u=           d=pf.1
146. 6 mul    %var_300.8, xdu.8(%var_838.4), %var_2F8.8 ; 18000DFCC u=sp+A0.4,sp+5D8.8 d=sp+5E0.8
146. 7 mov    #0x7B.4, %var_8A8.4     ; 18000E03F u=           d=sp+30.4
146. 8 goto   @3                      ; 18000E047 u=
146. 8
147. 0 ; 1WAY-BLOCK 147 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E04C END=18000E08F] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
147. 0 ; USE: ds.2,sp+738.1,sp+740..750,(GLBLOW,sp+0..738,sp+739.7,sp+750..,SHADOW,ARGS,GLBHIGH)
147. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+750..760
147. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
147. 0 or     %var_190.8, %var_198.8, %var_188.8 ; 18000E05C u=sp+740..750 d=sp+750.8
147. 1 mov    #0.1, cf.1              ; 18000E06C u=           d=cf.1
147. 2 mov    #0.1, of.1              ; 18000E06C u=           d=of.1
147. 3 setz   xdu.4((%var_1A0.1 & #0xF.1)), #0.4, zf.1 ; 18000E06C u=sp+738.1   d=zf.1
147. 4 setp   xdu.4((%var_1A0.1 & #0xF.1)), #0.4, pf.1 ; 18000E06C u=sp+738.1   d=pf.1
147. 5 mov    #0.1, sf.1              ; 18000E06C u=           d=sf.1
147. 6 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000E06F u=           d=rcx.8
147. 7 xdu    [ds.2:(xdu.8((%var_1A0.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1, rax.8 ; 18000E076 u=ds.2,sp+738.1,(GLBLOW,sp+0..738,sp+739..,SHADOW,ARGS,GLBHIGH) d=rax.8
147. 8 xdu    [ds.2:(xdu.8((%var_1A0.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1, %var_180.8 ; 18000E07A u=ds.2,sp+738.1,(GLBLOW,sp+0..738,sp+739..,SHADOW,ARGS,GLBHIGH) d=sp+758.8
147. 9 mov    #0xB9.4, %var_8A8.4     ; 18000E082 u=           d=sp+30.4
147.10 goto   @3                      ; 18000E08A u=
147.10
148. 0 ; 1WAY-BLOCK 148 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E08F END=18000E0B5] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
148. 0 ; USE: sp+240.4
148. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+244.4
148. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
148. 0 mov    call !__ROL4__<fast:_DWORD %var_698.4,char #0xD.1>.4, eax.4 ; 18000E096 u=sp+240.4   d=eax.4
148. 1 mul    #5.4, eax.4, eax.4      ; 18000E099 split4 u=eax.4      d=eax.4
148. 2 cfadd  eax.4, #0xE6546B64.4, cf.1 ; 18000E09C u=eax.4      d=cf.1
148. 3 ofadd  #0xE6546B64.4, eax.4, of.1 ; 18000E09C u=eax.4      d=of.1
148. 4 setz   eax.4, #0x19AB949C.4, zf.1 ; 18000E09C u=eax.4      d=zf.1
148. 5 setp   eax.4, #0x19AB949C.4, pf.1 ; 18000E09C u=eax.4      d=pf.1
148. 6 sets   (eax.4-#0x19AB949C.4), sf.1 ; 18000E09C u=eax.4      d=sf.1
148. 7 xdu    (eax.4-#0x19AB949C.4), rax.8 ; 18000E09C u=eax.4      d=rax.8
148. 8 mov    eax.4, %var_694.4       ; 18000E0A1 u=eax.4      d=sp+244.4
148. 9 mov    #0xF5.4, %var_8A8.4     ; 18000E0A8 u=           d=sp+30.4
148.10 goto   @3                      ; 18000E0B0 u=
148.10
149. 0 ; 1WAY-BLOCK 149 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E0B5 END=18000E122] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
149. 0 ; USE: sp+228.8
149. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+230.4
149. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
149. 0 mul    #0x1B873593.4, (%var_6AC.4 | (%var_6B0.4 >>l #0x11.1)), eax.4 ; 18000E105 split4 u=sp+228.8   d=eax.4
149. 1 und    zf.1                    ; 18000E105 u=           d=zf.1
149. 2 und    sf.1                    ; 18000E105 u=           d=sf.1
149. 3 und    pf.1                    ; 18000E105 u=           d=pf.1
149. 4 cfshl  eax.4, #0xD.1, tt.1     ; 18000E10B u=eax.4      d=tt.1
149. 5 mov    call !__ROL4__<fast:_DWORD eax.4,char #0xD.1>.4, eax.4 ; 18000E10B u=eax.4      d=eax.4
149. 6 mov    tt.1, cf.1              ; 18000E10B u=tt.1       d=cf.1
149. 7 und    of.1                    ; 18000E10B u=           d=of.1
149. 8 xdu    eax.4, rax.8            ; 18000E10B u=eax.4      d=rax^4.4
149. 9 mov    eax.4, %var_6A8.4       ; 18000E10E u=eax.4      d=sp+230.4
149.10 mov    #0xF1.4, %var_8A8.4     ; 18000E115 u=           d=sp+30.4
149.11 goto   @3                      ; 18000E11D u=
149.11
150. 0 ; 1WAY-BLOCK 150 INBOUNDS: 4 OUTBOUNDS: 151 [START=18000E122 END=18000E198] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
150. 0 ; USE: rsp.8,ds.2,sp+51.1,sp+2F8.8,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..51,sp+52..2F8,sp+300..,SHADOW,ARGS,GLBHIGH)
150. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,sp+39.1,(r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..39,sp+3A..,RET,SHADOW,ARGS,GLBHIGH)
150. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
150. 0 mov    %var_5E0.8, rax.8       ; 18000E122 u=sp+2F8.8   d=rax.8
150. 1 or     [ds.2:(%var_5E0.8+&($byte_1802272E0).8)].1, %var_887.1, dl.1 ; 18000E173 u=ds.2,sp+51.1,sp+2F8.8,(GLBLOW,sp+0..51,sp+52..2F8,sp+300..,SHADOW,ARGS,GLBHIGH) d=dl.1
150. 2 cfadd  dl.1, #0xC6.1, cf.1     ; 18000E176 u=dl.1       d=cf.1
150. 3 ofadd  #0xC6.1, dl.1, of.1     ; 18000E176 u=dl.1       d=of.1
150. 4 setz   dl.1, #0x3A.1, zf.1     ; 18000E176 u=dl.1       d=zf.1
150. 5 setp   dl.1, #0x3A.1, pf.1     ; 18000E176 u=dl.1       d=pf.1
150. 6 sets   (dl.1-#0x3A.1), sf.1    ; 18000E176 u=dl.1       d=sf.1
150. 7 sub    dl.1, #0x3A.1, %var_89F.1 ; 18000E179 u=dl.1       d=sp+39.1
150. 8 add    rsp.8, #0x39.8, rcx.8   ; 18000E17D u=rsp.8      d=rcx.8
150. 9 mov    #0x15.8, rdx.8          ; 18000E182 u=           d=rdx.8
150.10 mov    #0x11.8, r8.8           ; 18000E187 u=           d=r8.8
150.11 mov    #0x56.8, r9.8           ; 18000E18D u=           d=r9.8
150.12 call   $sub_180143830          ; 18000E193 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
150.12
151. 0 ; 1WAY-BLOCK 151 INBOUNDS: 150 OUTBOUNDS: 3 [START=18000E198 END=18000E1A5] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
151. 0 ; DEF: sp+30.4
151. 0 mov    #0x10.4, %var_8A8.4     ; 18000E198 u=           d=sp+30.4
151. 1 goto   @3                      ; 18000E1A0 u=
151. 1
152. 0 ; 1WAY-BLOCK 152 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E1A5 END=18000E1D8] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
152. 0 ; USE: sp+248.4
152. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+24C.4
152. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
152. 0 xdu    (#0xC2B2AE35.4*((#0x85EBCA6B.4*%var_690.4) ^ ((#0x85EBCA6B.4*%var_690.4) >>l #0xD.1))), rax.8 ; 18000E1B7 u=sp+248.4   d=rax.8
152. 1 mov    #0.1, cf.1              ; 18000E1C2 u=           d=cf.1
152. 2 mov    #0.1, of.1              ; 18000E1C2 u=           d=of.1
152. 3 setz   (eax.4 ^ ((#0xC2B2AE35.4*((#0x85EBCA6B.4*%var_690.4) ^ ((#0x85EBCA6B.4*%var_690.4) >>l #0xD.1))) >>l #0x10.1)), #0.4, zf.1 ; 18000E1C2 u=eax.4,sp+248.4 d=zf.1
152. 4 setp   (eax.4 ^ ((#0xC2B2AE35.4*((#0x85EBCA6B.4*%var_690.4) ^ ((#0x85EBCA6B.4*%var_690.4) >>l #0xD.1))) >>l #0x10.1)), #0.4, pf.1 ; 18000E1C2 u=eax.4,sp+248.4 d=pf.1
152. 5 sets   (eax.4 ^ ((#0xC2B2AE35.4*((#0x85EBCA6B.4*%var_690.4) ^ ((#0x85EBCA6B.4*%var_690.4) >>l #0xD.1))) >>l #0x10.1)), sf.1 ; 18000E1C2 u=eax.4,sp+248.4 d=sf.1
152. 6 xdu    (eax.4 ^ ((#0xC2B2AE35.4*((#0x85EBCA6B.4*%var_690.4) ^ ((#0x85EBCA6B.4*%var_690.4) >>l #0xD.1))) >>l #0x10.1)), rcx.8 ; 18000E1C2 u=eax.4,sp+248.4 d=rcx.8
152. 7 xor    eax.4, ((#0xC2B2AE35.4*((#0x85EBCA6B.4*%var_690.4) ^ ((#0x85EBCA6B.4*%var_690.4) >>l #0xD.1))) >>l #0x10.1), %var_68C.4 ; 18000E1C4 u=eax.4,sp+248.4 d=sp+24C.4
152. 8 mov    #0xF7.4, %var_8A8.4     ; 18000E1CB u=           d=sp+30.4
152. 9 goto   @3                      ; 18000E1D3 u=
152. 9
153. 0 ; 1WAY-BLOCK 153 INBOUNDS: 4 OUTBOUNDS: 154 [START=18000E1D8 END=18000E211] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
153. 0 ; USE: ds.2,sp+24C.4,sp+2B0..2C0,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..24C,sp+250..2B0,sp+2C0..,SHADOW,ARGS,GLBHIGH)
153. 0 ; DEF: rax.16,rcx.8,r8.8,r9.8,sp+20.4,sp+28.8,(cf.1,zf.1,sf.1,of.1,pf.1,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..20,sp+24.4,sp+30..,RET,SHADOW,ARGS,GLBHIGH)
153. 0 ldx    ds.2, %var_628.8, r9.8  ; 18000E1E0 u=ds.2,sp+2B0.8,(GLBLOW,sp+0..2B0,sp+2B8..,SHADOW,ARGS,GLBHIGH) d=r9.8
153. 1 xdu    [ds.2:%var_620.8].4, rdx.8 ; 18000E1EB u=ds.2,sp+2B8.8,(GLBLOW,sp+0..2B8,sp+2C0..,SHADOW,ARGS,GLBHIGH) d=rdx.8
153. 2 xdu    %var_68C.4, rax.8       ; 18000E1ED u=sp+24C.4   d=rax.8
153. 3 mov    %var_68C.4, %var_8B8.4  ; 18000E1F4 u=sp+24C.4   d=sp+20.4
153. 4 mov    #6.8, %var_8B0.8        ; 18000E1F8 u=           d=sp+28.8
153. 5 mov    #0x1B.8, rcx.8          ; 18000E201 u=           d=rcx.8
153. 6 mov    #0x3A.8, r8.8           ; 18000E206 u=           d=r8.8
153. 7 call   $sub_1801E9A40          ; 18000E20C u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
153. 7
154. 0 ; 2WAY-BLOCK 154 INBOUNDS: 153 OUTBOUNDS: 155 293 [START=18000E211 END=18000E27A] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
154. 0 ; USE: al.1,sp+74.4
154. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8,sp+D4.4
154. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
154. 0 xdu    (%var_864.4+#1.4), rcx.8 ; 18000E269 u=sp+74.4    d=rcx.8
154. 1 add    %var_864.4, #1.4, %var_804.4 ; 18000E26B u=sp+74.4    d=sp+D4.4
154. 2 mov    #0.1, cf.1              ; 18000E272 u=           d=cf.1
154. 3 mov    #0.1, of.1              ; 18000E272 u=           d=of.1
154. 4 setz   al.1, #0.1, zf.1        ; 18000E272 u=al.1       d=zf.1
154. 5 setp   al.1, #0.1, pf.1        ; 18000E272 u=al.1       d=pf.1
154. 6 sets   al.1, sf.1              ; 18000E272 u=al.1       d=sf.1
154. 7 jz     al.1, #0.1, @293        ; 18000E274 u=al.1
154. 7
155. 0 ; 1WAY-BLOCK 155 INBOUNDS: 154 OUTBOUNDS: 3 [START=18000E27A END=18000E287] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
155. 0 ; DEF: sp+30.4
155. 0 mov    #0xB.4, %var_8A8.4      ; 18000E27A u=           d=sp+30.4
155. 1 goto   @3                      ; 18000E282 u=
155. 1
156. 0 ; 1WAY-BLOCK 156 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E287 END=18000E336] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
156. 0 ; USE: sp+1BC.8,sp+658.1
156. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+1C4.4,sp+660.8
156. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
156. 0 or     %var_71C.4, (#0x100000.4*%var_718.4), %var_714.4 ; 18000E298 u=sp+1BC.8   d=sp+1C4.4
156. 1 xdu    (%var_280.1 & #0xF.1), rax.8 ; 18000E314 u=sp+658.1   d=rax.8
156. 2 cfadd  rax.8, &($p_InLoadOrderModuleList_2).8, cf.1 ; 18000E31E u=rax.8      d=cf.1
156. 3 ofadd  rax.8, &($p_InLoadOrderModuleList_2).8, of.1 ; 18000E31E u=rax.8      d=of.1
156. 4 setz   (rax.8+&($p_InLoadOrderModuleList_2).8), #0.8, zf.1 ; 18000E31E u=rax.8      d=zf.1
156. 5 setp   (rax.8+&($p_InLoadOrderModuleList_2).8), #0.8, pf.1 ; 18000E31E u=rax.8      d=pf.1
156. 6 sets   (rax.8+&($p_InLoadOrderModuleList_2).8), sf.1 ; 18000E31E u=rax.8      d=sf.1
156. 7 add    rax.8, &($p_InLoadOrderModuleList_2).8, rcx.8 ; 18000E31E u=rax.8      d=rcx.8
156. 8 add    rax.8, &($p_InLoadOrderModuleList_2).8, %var_278.8 ; 18000E321 u=rax.8      d=sp+660.8
156. 9 mov    #0x9C.4, %var_8A8.4     ; 18000E329 u=           d=sp+30.4
156.10 goto   @3                      ; 18000E331 u=
156.10
157. 0 ; 1WAY-BLOCK 157 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E336 END=18000E412] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
157. 0 ; USE: sp+1AC.4
157. 0 ; DEF: rax.8,sp+30.4,sp+B4.4
157. 0 ; DNU: rax.8
157. 0 xdu    %var_72C.4, rax.8       ; 18000E3F7 u=sp+1AC.4   d=rax.8
157. 1 mov    %var_72C.4, %var_824.4  ; 18000E3FE u=sp+1AC.4   d=sp+B4.4
157. 2 mov    #0x96.4, %var_8A8.4     ; 18000E405 u=           d=sp+30.4
157. 3 goto   @3                      ; 18000E40D u=
157. 3
158. 0 ; 1WAY-BLOCK 158 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E412 END=18000E441] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
158. 0 ; USE: sp+218.4
158. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+21C.4
158. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
158. 0 xdu    (#0xC2B2AE35.4*(%var_6C0.4 ^ (%var_6C0.4 >>l #0xD.1))), rax.8 ; 18000E420 u=sp+218.4   d=rax.8
158. 1 mov    #0.1, cf.1              ; 18000E42B u=           d=cf.1
158. 2 mov    #0.1, of.1              ; 18000E42B u=           d=of.1
158. 3 setz   (eax.4 ^ ((#0xC2B2AE35.4*(%var_6C0.4 ^ (%var_6C0.4 >>l #0xD.1))) >>l #0x10.1)), #0.4, zf.1 ; 18000E42B u=eax.4,sp+218.4 d=zf.1
158. 4 setp   (eax.4 ^ ((#0xC2B2AE35.4*(%var_6C0.4 ^ (%var_6C0.4 >>l #0xD.1))) >>l #0x10.1)), #0.4, pf.1 ; 18000E42B u=eax.4,sp+218.4 d=pf.1
158. 5 sets   (eax.4 ^ ((#0xC2B2AE35.4*(%var_6C0.4 ^ (%var_6C0.4 >>l #0xD.1))) >>l #0x10.1)), sf.1 ; 18000E42B u=eax.4,sp+218.4 d=sf.1
158. 6 xdu    (eax.4 ^ ((#0xC2B2AE35.4*(%var_6C0.4 ^ (%var_6C0.4 >>l #0xD.1))) >>l #0x10.1)), rcx.8 ; 18000E42B u=eax.4,sp+218.4 d=rcx.8
158. 7 xor    eax.4, ((#0xC2B2AE35.4*(%var_6C0.4 ^ (%var_6C0.4 >>l #0xD.1))) >>l #0x10.1), %var_6BC.4 ; 18000E42D u=eax.4,sp+218.4 d=sp+21C.4
158. 8 mov    #0xD9.4, %var_8A8.4     ; 18000E434 u=           d=sp+30.4
158. 9 goto   @3                      ; 18000E43C u=
158. 9
159. 0 ; 1WAY-BLOCK 159 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E441 END=18000E509] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
159. 0 ; USE: sp+810.1,sp+838..848
159. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+848..858
159. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
159. 0 or     %var_A0@8.8, %var_A0.8, %var_90.8 ; 18000E451 u=sp+838..848 d=sp+848.8
159. 1 xdu    (%var_C8.1 & #0xF.1), rax.8 ; 18000E4E7 u=sp+810.1   d=rax.8
159. 2 cfadd  rax.8, &($loc_18022725F@1).8, cf.1 ; 18000E4F1 u=rax.8      d=cf.1
159. 3 ofadd  rax.8, &($loc_18022725F@1).8, of.1 ; 18000E4F1 u=rax.8      d=of.1
159. 4 setz   (rax.8+&($loc_18022725F@1).8), #0.8, zf.1 ; 18000E4F1 u=rax.8      d=zf.1
159. 5 setp   (rax.8+&($loc_18022725F@1).8), #0.8, pf.1 ; 18000E4F1 u=rax.8      d=pf.1
159. 6 sets   (rax.8+&($loc_18022725F@1).8), sf.1 ; 18000E4F1 u=rax.8      d=sf.1
159. 7 add    rax.8, &($loc_18022725F@1).8, rcx.8 ; 18000E4F1 u=rax.8      d=rcx.8
159. 8 add    rax.8, &($loc_18022725F@1).8, %var_88.8 ; 18000E4F4 u=rax.8      d=sp+850.8
159. 9 mov    #0xE7.4, %var_8A8.4     ; 18000E4FC u=           d=sp+30.4
159.10 goto   @3                      ; 18000E504 u=
159.10
160. 0 ; 1WAY-BLOCK 160 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E509 END=18000E59C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
160. 0 ; USE: ds.2,sp+3B.1,sp+1B8.4,(GLBLOW,sp+0..3B,sp+3C..1B8,sp+1BC..,SHADOW,ARGS,GLBHIGH)
160. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+1BC.4
160. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
160. 0 mov    &($p_InLoadOrderModuleList_2).8, rcx.8 ; 18000E511 u=           d=rcx.8
160. 1 mov    #0.1, cf.1              ; 18000E581 u=           d=cf.1
160. 2 mov    #0.1, of.1              ; 18000E581 u=           d=of.1
160. 3 setz   (%var_720.4 | xdu.4([ds.2:(xdu.8((%var_89D.1 & #0xF.1))+&($p_InLoadOrderModuleList_2).8)].1)), #0.4, zf.1 ; 18000E581 u=ds.2,sp+3B.1,sp+1B8.4,(GLBLOW,sp+0..3B,sp+3C..1B8,sp+1BC..,SHADOW,ARGS,GLBHIGH) d=zf.1
160. 4 setp   (%var_720.4 | xdu.4([ds.2:(xdu.8((%var_89D.1 & #0xF.1))+&($p_InLoadOrderModuleList_2).8)].1)), #0.4, pf.1 ; 18000E581 u=ds.2,sp+3B.1,sp+1B8.4,(GLBLOW,sp+0..3B,sp+3C..1B8,sp+1BC..,SHADOW,ARGS,GLBHIGH) d=pf.1
160. 5 sets   (%var_720.4 | xdu.4([ds.2:(xdu.8((%var_89D.1 & #0xF.1))+&($p_InLoadOrderModuleList_2).8)].1)), sf.1 ; 18000E581 u=ds.2,sp+3B.1,sp+1B8.4,(GLBLOW,sp+0..3B,sp+3C..1B8,sp+1BC..,SHADOW,ARGS,GLBHIGH) d=sf.1
160. 6 xdu    (%var_720.4 | xdu.4([ds.2:(xdu.8((%var_89D.1 & #0xF.1))+&($p_InLoadOrderModuleList_2).8)].1)), rax.8 ; 18000E581 u=ds.2,sp+3B.1,sp+1B8.4,(GLBLOW,sp+0..3B,sp+3C..1B8,sp+1BC..,SHADOW,ARGS,GLBHIGH) d=rax.8
160. 7 or     %var_720.4, xdu.4([ds.2:(xdu.8((%var_89D.1 & #0xF.1))+&($p_InLoadOrderModuleList_2).8)].1), %var_71C.4 ; 18000E588 u=ds.2,sp+3B.1,sp+1B8.4,(GLBLOW,sp+0..3B,sp+3C..1B8,sp+1BC..,SHADOW,ARGS,GLBHIGH) d=sp+1BC.4
160. 8 mov    #0x9A.4, %var_8A8.4     ; 18000E58F u=           d=sp+30.4
160. 9 goto   @3                      ; 18000E597 u=
160. 9
161. 0 ; 1WAY-BLOCK 161 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E59C END=18000E65E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
161. 0 ; USE: ds.2,sp+7A8.1,sp+800.8,(GLBLOW,sp+0..7A8,sp+7A9..800,sp+808..,SHADOW,ARGS,GLBHIGH)
161. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+808.8
161. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
161. 0 mov    &($p_InLoadOrderModuleList_7).8, rcx.8 ; 18000E5E5 u=           d=rcx.8
161. 1 or     %var_D8.8, xdu.8((#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_130.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1))), rax.8 ; 18000E5F3 u=ds.2,sp+7A8.1,sp+800.8,(GLBLOW,sp+0..7A8,sp+7A9..800,sp+808..,SHADOW,ARGS,GLBHIGH) d=rax.8
161. 2 mov    #0.1, cf.1              ; 18000E5F3 u=           d=cf.1
161. 3 mov    #0.1, of.1              ; 18000E5F3 u=           d=of.1
161. 4 setz   (%var_D8.8 | xdu.8((#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_130.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1)))), #0.8, zf.1 ; 18000E5F3 u=ds.2,sp+7A8.1,sp+800.8,(GLBLOW,sp+0..7A8,sp+7A9..800,sp+808..,SHADOW,ARGS,GLBHIGH) d=zf.1
161. 5 setp   (%var_D8.8 | xdu.8((#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_130.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1)))), #0.8, pf.1 ; 18000E5F3 u=ds.2,sp+7A8.1,sp+800.8,(GLBLOW,sp+0..7A8,sp+7A9..800,sp+808..,SHADOW,ARGS,GLBHIGH) d=pf.1
161. 6 sets   (%var_D8.8 | xdu.8((#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_130.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1)))), sf.1 ; 18000E5F3 u=ds.2,sp+7A8.1,sp+800.8,(GLBLOW,sp+0..7A8,sp+7A9..800,sp+808..,SHADOW,ARGS,GLBHIGH) d=sf.1
161. 7 or     %var_D8.8, xdu.8((#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_130.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1))), %var_D0.8 ; 18000E5FB u=ds.2,sp+7A8.1,sp+800.8,(GLBLOW,sp+0..7A8,sp+7A9..800,sp+808..,SHADOW,ARGS,GLBHIGH) d=sp+808.8
161. 8 mov    #0xCF.4, %var_8A8.4     ; 18000E651 u=           d=sp+30.4
161. 9 goto   @3                      ; 18000E659 u=
161. 9
162. 0 ; 1WAY-BLOCK 162 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E65E END=18000E6DA] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
162. 0 ; USE: ds.2,sp+6A.1,sp+6A8.8,(GLBLOW,sp+0..6A,sp+6B..6A8,sp+6B0..,SHADOW,ARGS,GLBHIGH)
162. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+6B0.8
162. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
162. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000E6AF u=           d=rcx.8
162. 1 or     %var_230.8, xdu.8((#0x10000.4*xdu.4([ds.2:(xdu.8((%var_870@2.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), rax.8 ; 18000E6BD u=ds.2,sp+6A.1,sp+6A8.8,(GLBLOW,sp+0..6A,sp+6B..6A8,sp+6B0..,SHADOW,ARGS,GLBHIGH) d=rax.8
162. 2 mov    #0.1, cf.1              ; 18000E6BD u=           d=cf.1
162. 3 mov    #0.1, of.1              ; 18000E6BD u=           d=of.1
162. 4 setz   (%var_230.8 | xdu.8((#0x10000.4*xdu.4([ds.2:(xdu.8((%var_870@2.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)))), #0.8, zf.1 ; 18000E6BD u=ds.2,sp+6A.1,sp+6A8.8,(GLBLOW,sp+0..6A,sp+6B..6A8,sp+6B0..,SHADOW,ARGS,GLBHIGH) d=zf.1
162. 5 setp   (%var_230.8 | xdu.8((#0x10000.4*xdu.4([ds.2:(xdu.8((%var_870@2.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)))), #0.8, pf.1 ; 18000E6BD u=ds.2,sp+6A.1,sp+6A8.8,(GLBLOW,sp+0..6A,sp+6B..6A8,sp+6B0..,SHADOW,ARGS,GLBHIGH) d=pf.1
162. 6 sets   (%var_230.8 | xdu.8((#0x10000.4*xdu.4([ds.2:(xdu.8((%var_870@2.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)))), sf.1 ; 18000E6BD u=ds.2,sp+6A.1,sp+6A8.8,(GLBLOW,sp+0..6A,sp+6B..6A8,sp+6B0..,SHADOW,ARGS,GLBHIGH) d=sf.1
162. 7 or     %var_230.8, xdu.8((#0x10000.4*xdu.4([ds.2:(xdu.8((%var_870@2.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), %var_228.8 ; 18000E6C5 u=ds.2,sp+6A.1,sp+6A8.8,(GLBLOW,sp+0..6A,sp+6B..6A8,sp+6B0..,SHADOW,ARGS,GLBHIGH) d=sp+6B0.8
162. 8 mov    #0xAC.4, %var_8A8.4     ; 18000E6CD u=           d=sp+30.4
162. 9 goto   @3                      ; 18000E6D5 u=
162. 9
163. 0 ; 1WAY-BLOCK 163 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E6DA END=18000E782] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
163. 0 ; USE: ds.2,sp+90.8,sp+818.8,(GLBLOW,sp+0..90,sp+98..818,sp+820..,SHADOW,ARGS,GLBHIGH)
163. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+820..838
163. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
163. 0 xdu    (#0x1000.4*xdu.4([ds.2:%var_C0.8].1)), %var_B8.8 ; 18000E6E8 u=ds.2,sp+818.8,(GLBLOW,sp+0..818,sp+820..,SHADOW,ARGS,GLBHIGH) d=sp+820.8
163. 1 shr    %var_848.8, #0x10.1, rcx.8 ; 18000E75D u=sp+90.8    d=rcx.8
163. 2 shr    %var_848.8, #0x10.1, %var_B0.8 ; 18000E761 u=sp+90.8    d=sp+828.8
163. 3 cfshr  %var_848.8, #0x14.1, cf.1 ; 18000E769 u=sp+90.8    d=cf.1
163. 4 shr    %var_848.8, #0x14.1, rax.8 ; 18000E769 u=sp+90.8    d=rax.8
163. 5 und    of.1                    ; 18000E769 u=           d=of.1
163. 6 setz   (%var_848.8 >>l #0x14.1), #0.8, zf.1 ; 18000E769 u=sp+90.8    d=zf.1
163. 7 setp   (%var_848.8 >>l #0x14.1), #0.8, pf.1 ; 18000E769 u=sp+90.8    d=pf.1
163. 8 mov    #0.1, sf.1              ; 18000E769 u=           d=sf.1
163. 9 shr    %var_848.8, #0x14.1, %var_A8.8 ; 18000E76D u=sp+90.8    d=sp+830.8
163.10 mov    #0xE4.4, %var_8A8.4     ; 18000E775 u=           d=sp+30.4
163.11 goto   @3                      ; 18000E77D u=
163.11
164. 0 ; 1WAY-BLOCK 164 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E782 END=18000E837] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
164. 0 ; USE: sp+5C.1,sp+68.8,sp+760.8
164. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+768..778
164. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
164. 0 or     %var_178.8, (#0x100000000.8*xdu.8(%var_87C.1)), %var_170.8 ; 18000E793 u=sp+5C.1,sp+760.8 d=sp+768.8
164. 1 shr    %var_870.8, #0x3C.1, rax.8 ; 18000E7A0 u=sp+68.8    d=rax.8
164. 2 cfadd  (%var_870.8 >>l #0x3C.1), &($p_InLoadOrderModuleList_5).8, cf.1 ; 18000E7AB u=sp+68.8    d=cf.1
164. 3 ofadd  (%var_870.8 >>l #0x3C.1), &($p_InLoadOrderModuleList_5).8, of.1 ; 18000E7AB u=sp+68.8    d=of.1
164. 4 setz   ((%var_870.8 >>l #0x3C.1)+&($p_InLoadOrderModuleList_5).8), #0.8, zf.1 ; 18000E7AB u=sp+68.8    d=zf.1
164. 5 setp   ((%var_870.8 >>l #0x3C.1)+&($p_InLoadOrderModuleList_5).8), #0.8, pf.1 ; 18000E7AB u=sp+68.8    d=pf.1
164. 6 sets   ((%var_870.8 >>l #0x3C.1)+&($p_InLoadOrderModuleList_5).8), sf.1 ; 18000E7AB u=sp+68.8    d=sf.1
164. 7 add    (%var_870.8 >>l #0x3C.1), &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000E7AB u=sp+68.8    d=rcx.8
164. 8 add    (%var_870.8 >>l #0x3C.1), &($p_InLoadOrderModuleList_5).8, %var_168.8 ; 18000E7AE u=sp+68.8    d=sp+770.8
164. 9 mov    #0xBB.4, %var_8A8.4     ; 18000E82A u=           d=sp+30.4
164.10 goto   @3                      ; 18000E832 u=
164.10
165. 0 ; 1WAY-BLOCK 165 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E837 END=18000E868] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
165. 0 ; USE: ds.2,sp+890.8,(GLBLOW,sp+0..890,sp+898..,SHADOW,ARGS,GLBHIGH)
165. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+238.8
165. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
165. 0 ldx    ds.2, %var_48.8, eax.4  ; 18000E83F u=ds.2,sp+890.8,(GLBLOW,sp+0..890,sp+898..,SHADOW,ARGS,GLBHIGH) d=eax.4
165. 1 xdu    (#0xCC9E2D51.4*[ds.2:%var_48.8].4), rcx.8 ; 18000E841 u=ds.2,sp+890.8,(GLBLOW,sp+0..890,sp+898..,SHADOW,ARGS,GLBHIGH) d=rcx.8
165. 2 mul    #0xCC9E2D51.4, [ds.2:%var_48.8].4, %var_6A0.4 ; 18000E847 split4 u=ds.2,sp+890.8,(GLBLOW,sp+0..890,sp+898..,SHADOW,ARGS,GLBHIGH) d=sp+238.4
165. 3 setnz  high.4((#0x16A88000.8*xds.8(eax.4))), #0.4, cf.1 ; 18000E84E u=eax.4      d=cf.1
165. 4 setnz  high.4((#0x16A88000.8*xds.8(eax.4))), #0.4, of.1 ; 18000E84E u=eax.4      d=of.1
165. 5 und    zf.1                    ; 18000E84E u=           d=zf.1
165. 6 und    sf.1                    ; 18000E84E u=           d=sf.1
165. 7 und    pf.1                    ; 18000E84E u=           d=pf.1
165. 8 xdu    (#0x16A88000.4*eax.4), rax.8 ; 18000E84E u=eax.4      d=rax.8
165. 9 mov    eax.4, %var_69C.4       ; 18000E854 u=eax.4      d=sp+23C.4
165.10 mov    #0xF3.4, %var_8A8.4     ; 18000E85B u=           d=sp+30.4
165.11 goto   @3                      ; 18000E863 u=
165.11
166. 0 ; 1WAY-BLOCK 166 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E868 END=18000E8AF] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
166. 0 ; USE: ds.2,sp+68.8,sp+730.8,(GLBLOW,sp+0..68,sp+70..730,sp+738..,SHADOW,ARGS,GLBHIGH)
166. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+738..748
166. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
166. 0 shr    %var_870.8, #0x28.1, %var_1A0.8 ; 18000E874 u=sp+68.8    d=sp+738.8
166. 1 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000E883 u=           d=rcx.8
166. 2 or     %var_1A8.8, (#0x100000000000.8*xdu.8([ds.2:(((%var_870.8 >>l #0x2C.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1)), rax.8 ; 18000E892 u=ds.2,sp+68.8,sp+730.8,(GLBLOW,sp+0..68,sp+70..730,sp+738..,SHADOW,ARGS,GLBHIGH) d=rax.8
166. 3 mov    #0.1, cf.1              ; 18000E892 u=           d=cf.1
166. 4 mov    #0.1, of.1              ; 18000E892 u=           d=of.1
166. 5 setz   (%var_1A8.8 | (#0x100000000000.8*xdu.8([ds.2:(((%var_870.8 >>l #0x2C.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, zf.1 ; 18000E892 u=ds.2,sp+68.8,sp+730.8,(GLBLOW,sp+0..68,sp+70..730,sp+738..,SHADOW,ARGS,GLBHIGH) d=zf.1
166. 6 setp   (%var_1A8.8 | (#0x100000000000.8*xdu.8([ds.2:(((%var_870.8 >>l #0x2C.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, pf.1 ; 18000E892 u=ds.2,sp+68.8,sp+730.8,(GLBLOW,sp+0..68,sp+70..730,sp+738..,SHADOW,ARGS,GLBHIGH) d=pf.1
166. 7 sets   (%var_1A8.8 | (#0x100000000000.8*xdu.8([ds.2:(((%var_870.8 >>l #0x2C.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1))), sf.1 ; 18000E892 u=ds.2,sp+68.8,sp+730.8,(GLBLOW,sp+0..68,sp+70..730,sp+738..,SHADOW,ARGS,GLBHIGH) d=sf.1
166. 8 or     %var_1A8.8, (#0x100000000000.8*xdu.8([ds.2:(((%var_870.8 >>l #0x2C.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1)), %var_198.8 ; 18000E89A u=ds.2,sp+68.8,sp+730.8,(GLBLOW,sp+0..68,sp+70..730,sp+738..,SHADOW,ARGS,GLBHIGH) d=sp+740.8
166. 9 mov    #0xB7.4, %var_8A8.4     ; 18000E8A2 u=           d=sp+30.4
166.10 goto   @3                      ; 18000E8AA u=
166.10
167. 0 ; 1WAY-BLOCK 167 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E8AF END=18000E8F2] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
167. 0 ; USE: ds.2,sp+700.1,sp+750..760,(GLBLOW,sp+0..700,sp+701..750,sp+760..,SHADOW,ARGS,GLBHIGH)
167. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+5C.1,sp+760.8
167. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
167. 0 or     %var_188.8, (#0x10000000000.8*%var_180.8), %var_178.8 ; 18000E8C3 u=sp+750..760 d=sp+760.8
167. 1 mov    #0.1, cf.1              ; 18000E8D3 u=           d=cf.1
167. 2 mov    #0.1, of.1              ; 18000E8D3 u=           d=of.1
167. 3 setz   xdu.4((%var_1D8.1 & #0xF.1)), #0.4, zf.1 ; 18000E8D3 u=sp+700.1   d=zf.1
167. 4 setp   xdu.4((%var_1D8.1 & #0xF.1)), #0.4, pf.1 ; 18000E8D3 u=sp+700.1   d=pf.1
167. 5 mov    #0.1, sf.1              ; 18000E8D3 u=           d=sf.1
167. 6 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000E8D6 u=           d=rcx.8
167. 7 xdu    [ds.2:(xdu.8((%var_1D8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1, rax.8 ; 18000E8DD u=ds.2,sp+700.1,(GLBLOW,sp+0..700,sp+701..,SHADOW,ARGS,GLBHIGH) d=rax.8
167. 8 ldx    ds.2, (xdu.8((%var_1D8.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8), %var_87C.1 ; 18000E8E1 u=ds.2,sp+700.1,(GLBLOW,sp+0..700,sp+701..,SHADOW,ARGS,GLBHIGH) d=sp+5C.1
167. 9 mov    #0xBA.4, %var_8A8.4     ; 18000E8E5 u=           d=sp+30.4
167.10 goto   @3                      ; 18000E8ED u=
167.10
168. 0 ; 1WAY-BLOCK 168 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E8F2 END=18000E9BA] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
168. 0 ; USE: sp+90.8
168. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+810..820
168. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
168. 0 shr    %var_848.8, #8.1, %var_C8.8 ; 18000E946 u=sp+90.8    d=sp+810.8
168. 1 xdu    (%var_848.2 >>l #0xC.1), rax.8 ; 18000E998 u=sp+90.2    d=rax.8
168. 2 cfadd  rax.8, &($loc_18022725F@1).8, cf.1 ; 18000E9A2 u=rax.8      d=cf.1
168. 3 ofadd  rax.8, &($loc_18022725F@1).8, of.1 ; 18000E9A2 u=rax.8      d=of.1
168. 4 setz   (rax.8+&($loc_18022725F@1).8), #0.8, zf.1 ; 18000E9A2 u=rax.8      d=zf.1
168. 5 setp   (rax.8+&($loc_18022725F@1).8), #0.8, pf.1 ; 18000E9A2 u=rax.8      d=pf.1
168. 6 sets   (rax.8+&($loc_18022725F@1).8), sf.1 ; 18000E9A2 u=rax.8      d=sf.1
168. 7 add    rax.8, &($loc_18022725F@1).8, rcx.8 ; 18000E9A2 u=rax.8      d=rcx.8
168. 8 add    rax.8, &($loc_18022725F@1).8, %var_C0.8 ; 18000E9A5 u=rax.8      d=sp+818.8
168. 9 mov    #0xE3.4, %var_8A8.4     ; 18000E9AD u=           d=sp+30.4
168.10 goto   @3                      ; 18000E9B5 u=
168.10
169. 0 ; 1WAY-BLOCK 169 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000E9BA END=18000EA2A] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
169. 0 ; USE: ds.2,sp+828.1,(GLBLOW,sp+0..828,sp+829..,SHADOW,ARGS,GLBHIGH)
169. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+870.8
169. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
169. 0 mov    &($loc_18022725F@1).8, rcx.8 ; 18000EA07 u=           d=rcx.8
169. 1 xdu    [ds.2:(xdu.8((%var_B0.1 & #0xF.1))+&($loc_18022725F@1).8)].1, eax.4 ; 18000EA0E u=ds.2,sp+828.1,(GLBLOW,sp+0..828,sp+829..,SHADOW,ARGS,GLBHIGH) d=eax.4
169. 2 cfshl  eax.4, #0x10.1, cf.1    ; 18000EA12 u=eax.4      d=cf.1
169. 3 mul    #0x10000.4, eax.4, eax.4 ; 18000EA12 u=eax.4      d=eax.4
169. 4 und    of.1                    ; 18000EA12 u=           d=of.1
169. 5 setz   eax.4, #0.4, zf.1       ; 18000EA12 u=eax.4      d=zf.1
169. 6 setp   eax.4, #0.4, pf.1       ; 18000EA12 u=eax.4      d=pf.1
169. 7 sets   eax.4, sf.1             ; 18000EA12 u=eax.4      d=sf.1
169. 8 xdu    eax.4, rax.8            ; 18000EA12 u=eax.4      d=rax^4.4
169. 9 xdu    eax.4, %var_68.8        ; 18000EA15 u=eax.4      d=sp+870.8
169.10 mov    #0xEB.4, %var_8A8.4     ; 18000EA1D u=           d=sp+30.4
169.11 goto   @3                      ; 18000EA25 u=
169.11
170. 0 ; 1WAY-BLOCK 170 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000EA2A END=18000EAD8] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
170. 0 ; USE: sp+230.4,sp+2E0.8
170. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+234.4,sp+890.8
170. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
170. 0 sub    (#5.4*%var_6A8.4), #0x19AB949C.4, %var_6A4.4 ; 18000EA39 u=sp+230.4   d=sp+234.4
170. 1 cfadd  %var_5F8.8, #4.8, cf.1  ; 18000EA48 u=sp+2E0.8   d=cf.1
170. 2 ofadd  #4.8, %var_5F8.8, of.1  ; 18000EA48 u=sp+2E0.8   d=of.1
170. 3 setz   (%var_5F8.8+#4.8), #0.8, zf.1 ; 18000EA48 u=sp+2E0.8   d=zf.1
170. 4 setp   (%var_5F8.8+#4.8), #0.8, pf.1 ; 18000EA48 u=sp+2E0.8   d=pf.1
170. 5 sets   (%var_5F8.8+#4.8), sf.1 ; 18000EA48 u=sp+2E0.8   d=sf.1
170. 6 add    %var_5F8.8, #4.8, rax.8 ; 18000EA48 u=sp+2E0.8   d=rax.8
170. 7 add    %var_5F8.8, #4.8, %var_48.8 ; 18000EA4C u=sp+2E0.8   d=sp+890.8
170. 8 mov    #0xF2.4, %var_8A8.4     ; 18000EACB u=           d=sp+30.4
170. 9 goto   @3                      ; 18000EAD3 u=
170. 9
171. 0 ; 1WAY-BLOCK 171 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000EAD8 END=18000EB6F] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
171. 0 ; USE: ds.2,sp+93.1,(GLBLOW,sp+0..93,sp+94..,SHADOW,ARGS,GLBHIGH)
171. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+840.8
171. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
171. 0 mov    &($loc_18022725F@1).8, rcx.8 ; 18000EB4C u=           d=rcx.8
171. 1 xdu    [ds.2:(xdu.8((%var_848@3.1 & #0xF.1))+&($loc_18022725F@1).8)].1, eax.4 ; 18000EB53 u=ds.2,sp+93.1,(GLBLOW,sp+0..93,sp+94..,SHADOW,ARGS,GLBHIGH) d=eax.4
171. 2 cfshl  eax.4, #0x18.1, cf.1    ; 18000EB57 u=eax.4      d=cf.1
171. 3 mul    #0x1000000.4, eax.4, eax.4 ; 18000EB57 u=eax.4      d=eax.4
171. 4 und    of.1                    ; 18000EB57 u=           d=of.1
171. 5 setz   eax.4, #0.4, zf.1       ; 18000EB57 u=eax.4      d=zf.1
171. 6 setp   eax.4, #0.4, pf.1       ; 18000EB57 u=eax.4      d=pf.1
171. 7 sets   eax.4, sf.1             ; 18000EB57 u=eax.4      d=sf.1
171. 8 xdu    eax.4, rax.8            ; 18000EB57 u=eax.4      d=rax^4.4
171. 9 xdu    eax.4, %var_A0@8.8      ; 18000EB5A u=eax.4      d=sp+840.8
171.10 mov    #0xE6.4, %var_8A8.4     ; 18000EB62 u=           d=sp+30.4
171.11 goto   @3                      ; 18000EB6A u=
171.11
172. 0 ; 1WAY-BLOCK 172 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000EB6F END=18000EBDD] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
172. 0 ; USE: ds.2,sp+2D0.8,sp+888.4,(GLBLOW,sp+0..2D0,sp+2D8..888,sp+88C..,SHADOW,ARGS,GLBHIGH)
172. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+2E0.8
172. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
172. 0 mov    #0.1, cf.1              ; 18000EB76 u=           d=cf.1
172. 1 mov    #0.1, of.1              ; 18000EB76 u=           d=of.1
172. 2 setz   (xdu.8(%var_50.4) ^ #0xAC.8), #0.8, zf.1 ; 18000EB76 u=sp+888.4   d=zf.1
172. 3 setp   (xdu.8(%var_50.4) ^ #0xAC.8), #0.8, pf.1 ; 18000EB76 u=sp+888.4   d=pf.1
172. 4 mov    #0.1, sf.1              ; 18000EB76 u=           d=sf.1
172. 5 mov    %var_608.8, rcx.8       ; 18000EB7C u=sp+2D0.8   d=rcx.8
172. 6 ldx    ds.2, (%var_608.8+(xdu.8(%var_50.4) ^ #0xAC.8)), rax.8 ; 18000EB84 u=ds.2,sp+2D0.8,sp+888.4,(GLBLOW,sp+0..2D0,sp+2D8..888,sp+88C..,SHADOW,ARGS,GLBHIGH) d=rax.8
172. 7 ldx    ds.2, (%var_608.8+(xdu.8(%var_50.4) ^ #0xAC.8)), %var_5F8.8 ; 18000EB88 u=ds.2,sp+2D0.8,sp+888.4,(GLBLOW,sp+0..2D0,sp+2D8..888,sp+88C..,SHADOW,ARGS,GLBHIGH) d=sp+2E0.8
172. 8 mov    #0xEE.4, %var_8A8.4     ; 18000EBD0 u=           d=sp+30.4
172. 9 goto   @3                      ; 18000EBD8 u=
172. 9
173. 0 ; 1WAY-BLOCK 173 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000EBDD END=18000EC5A] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
173. 0 ; USE: ds.2,sp+2E0.8,(GLBLOW,sp+0..2E0,sp+2E8..,SHADOW,ARGS,GLBHIGH)
173. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+228.8
173. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
173. 0 ldx    ds.2, %var_5F8.8, eax.4 ; 18000EBE5 u=ds.2,sp+2E0.8,(GLBLOW,sp+0..2E0,sp+2E8..,SHADOW,ARGS,GLBHIGH) d=eax.4
173. 1 xdu    (#0xCC9E2D51.4*[ds.2:%var_5F8.8].4), rcx.8 ; 18000EBE7 u=ds.2,sp+2E0.8,(GLBLOW,sp+0..2E0,sp+2E8..,SHADOW,ARGS,GLBHIGH) d=rcx.8
173. 2 mul    #0xCC9E2D51.4, [ds.2:%var_5F8.8].4, %var_6B0.4 ; 18000EBED split4 u=ds.2,sp+2E0.8,(GLBLOW,sp+0..2E0,sp+2E8..,SHADOW,ARGS,GLBHIGH) d=sp+228.4
173. 3 setnz  high.4((#0x16A88000.8*xds.8(eax.4))), #0.4, cf.1 ; 18000EC40 u=eax.4      d=cf.1
173. 4 setnz  high.4((#0x16A88000.8*xds.8(eax.4))), #0.4, of.1 ; 18000EC40 u=eax.4      d=of.1
173. 5 und    zf.1                    ; 18000EC40 u=           d=zf.1
173. 6 und    sf.1                    ; 18000EC40 u=           d=sf.1
173. 7 und    pf.1                    ; 18000EC40 u=           d=pf.1
173. 8 xdu    (#0x16A88000.4*eax.4), rax.8 ; 18000EC40 u=eax.4      d=rax.8
173. 9 mov    eax.4, %var_6AC.4       ; 18000EC46 u=eax.4      d=sp+22C.4
173.10 mov    #0xF0.4, %var_8A8.4     ; 18000EC4D u=           d=sp+30.4
173.11 goto   @3                      ; 18000EC55 u=
173.11
174. 0 ; 1WAY-BLOCK 174 INBOUNDS: 4 OUTBOUNDS: 175 [START=18000EC5A END=18000EC93] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
174. 0 ; USE: ds.2,sp+21C.4,sp+2B0..2C0,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..21C,sp+220..2B0,sp+2C0..,SHADOW,ARGS,GLBHIGH)
174. 0 ; DEF: rax.16,rcx.8,r8.8,r9.8,sp+20.4,sp+28.8,(cf.1,zf.1,sf.1,of.1,pf.1,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..20,sp+24.4,sp+30..,RET,SHADOW,ARGS,GLBHIGH)
174. 0 ldx    ds.2, %var_628.8, r9.8  ; 18000EC62 u=ds.2,sp+2B0.8,(GLBLOW,sp+0..2B0,sp+2B8..,SHADOW,ARGS,GLBHIGH) d=r9.8
174. 1 xdu    [ds.2:%var_620.8].4, rdx.8 ; 18000EC6D u=ds.2,sp+2B8.8,(GLBLOW,sp+0..2B8,sp+2C0..,SHADOW,ARGS,GLBHIGH) d=rdx.8
174. 2 xdu    %var_6BC.4, rax.8       ; 18000EC6F u=sp+21C.4   d=rax.8
174. 3 mov    %var_6BC.4, %var_8B8.4  ; 18000EC76 u=sp+21C.4   d=sp+20.4
174. 4 mov    #0x5A.8, %var_8B0.8     ; 18000EC7A u=           d=sp+28.8
174. 5 mov    #0x5F.8, rcx.8          ; 18000EC83 u=           d=rcx.8
174. 6 mov    #0x46.8, r8.8           ; 18000EC88 u=           d=r8.8
174. 7 call   $sub_1801E9A40          ; 18000EC8E u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
174. 7
175. 0 ; 2WAY-BLOCK 175 INBOUNDS: 174 OUTBOUNDS: 176 294 [START=18000EC93 END=18000EC9B] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
175. 0 ; USE: al.1
175. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1
175. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
175. 0 mov    #0.1, cf.1              ; 18000EC93 u=           d=cf.1
175. 1 mov    #0.1, of.1              ; 18000EC93 u=           d=of.1
175. 2 setz   al.1, #0.1, zf.1        ; 18000EC93 u=al.1       d=zf.1
175. 3 setp   al.1, #0.1, pf.1        ; 18000EC93 u=al.1       d=pf.1
175. 4 sets   al.1, sf.1              ; 18000EC93 u=al.1       d=sf.1
175. 5 jz     al.1, #0.1, @294        ; 18000EC95 u=al.1
175. 5
176. 0 ; 1WAY-BLOCK 176 INBOUNDS: 175 OUTBOUNDS: 3 [START=18000EC9B END=18000ECA8] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
176. 0 ; DEF: sp+30.4
176. 0 mov    #0xDF.4, %var_8A8.4     ; 18000EC9B u=           d=sp+30.4
176. 1 goto   @3                      ; 18000ECA3 u=
176. 1
177. 0 ; 1WAY-BLOCK 177 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000ECA8 END=18000ED48] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
177. 0 ; USE: sp+214.4
177. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+218.4
177. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx^4.4
177. 0 xdu    ((%var_6C4.4 ^ (%var_6C4.4 >>l #0x10.1)) ^ #8.4), rcx.8 ; 18000ED2B u=sp+214.4   d=rcx.8
177. 1 setnz  high.4((#-0x7A143595.8*xds.8(ecx.4))), #0.4, cf.1 ; 18000ED2E u=ecx.4      d=cf.1
177. 2 setnz  high.4((#-0x7A143595.8*xds.8(ecx.4))), #0.4, of.1 ; 18000ED2E u=ecx.4      d=of.1
177. 3 und    zf.1                    ; 18000ED2E u=           d=zf.1
177. 4 und    sf.1                    ; 18000ED2E u=           d=sf.1
177. 5 und    pf.1                    ; 18000ED2E u=           d=pf.1
177. 6 xdu    (#0x85EBCA6B.4*ecx.4), rax.8 ; 18000ED2E u=ecx.4      d=rax.8
177. 7 mul    #0x85EBCA6B.4, ecx.4, %var_6C0.4 ; 18000ED34 u=ecx.4      d=sp+218.4
177. 8 mov    #0xD8.4, %var_8A8.4     ; 18000ED3B u=           d=sp+30.4
177. 9 goto   @3                      ; 18000ED43 u=
177. 9
178. 0 ; 1WAY-BLOCK 178 INBOUNDS: 4 OUTBOUNDS: 179 [START=18000ED48 END=18000EE45] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
178. 0 ; USE: rsp.8,sp+10C.4,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..10C,sp+110..,SHADOW,ARGS,GLBHIGH)
178. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,sp+C4.4,(r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..C4,sp+C8..,RET,SHADOW,ARGS,GLBHIGH)
178. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
178. 0 setz   %var_7CC.4, #0x34B92CEE.4, zf.1 ; 18000ED4D u=sp+10C.4   d=zf.1
178. 1 setp   %var_7CC.4, #0x34B92CEE.4, pf.1 ; 18000ED4D u=sp+10C.4   d=pf.1
178. 2 sets   (%var_7CC.4-#0x34B92CEE.4), sf.1 ; 18000ED4D u=sp+10C.4   d=sf.1
178. 3 mov    call !__ROL4__<fast:_DWORD (%var_7CC.4-#0x34B92CEE.4),char #0xF.1>.4, eax.4 ; 18000EDB0 u=sp+10C.4   d=eax.4
178. 4 cfshl  (%var_7CC.4-#0x34B92CEE.4), #0xF.1, cf.1 ; 18000EDB0 u=sp+10C.4   d=cf.1
178. 5 und    of.1                    ; 18000EDB0 u=           d=of.1
178. 6 xdu    eax.4, rax.8            ; 18000EDB0 u=eax.4      d=rax^4.4
178. 7 mov    eax.4, %var_814.4       ; 18000EDB3 u=eax.4      d=sp+C4.4
178. 8 add    rsp.8, #0xC4.8, r9.8    ; 18000EE28 u=rsp.8      d=r9.8
178. 9 mov    #0x2B.8, rcx.8          ; 18000EE30 u=           d=rcx.8
178.10 mov    #0xF.8, rdx.8           ; 18000EE35 u=           d=rdx.8
178.11 mov    #0x25.8, r8.8           ; 18000EE3A u=           d=r8.8
178.12 call   $sub_180034460          ; 18000EE40 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
178.12
179. 0 ; 1WAY-BLOCK 179 INBOUNDS: 178 OUTBOUNDS: 3 [START=18000EE45 END=18000EE52] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
179. 0 ; DEF: sp+30.4
179. 0 mov    #0x17.4, %var_8A8.4     ; 18000EE45 u=           d=sp+30.4
179. 1 goto   @3                      ; 18000EE4D u=
179. 1
180. 0 ; 2WAY-BLOCK 180 INBOUNDS: 4 OUTBOUNDS: 181 296 [START=18000EE52 END=18000EE5D] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
180. 0 ; USE: sp+39.1
180. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1
180. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
180. 0 mov    #0.1, cf.1              ; 18000EE52 u=           d=cf.1
180. 1 mov    #0.1, of.1              ; 18000EE52 u=           d=of.1
180. 2 setz   %var_89F.1, #0.1, zf.1  ; 18000EE52 u=sp+39.1    d=zf.1
180. 3 setp   %var_89F.1, #0.1, pf.1  ; 18000EE52 u=sp+39.1    d=pf.1
180. 4 sets   %var_89F.1, sf.1        ; 18000EE52 u=sp+39.1    d=sf.1
180. 5 jz     %var_89F.1, #0.1, @296  ; 18000EE57 u=sp+39.1
180. 5
181. 0 ; 1WAY-BLOCK 181 INBOUNDS: 180 OUTBOUNDS: 3 [START=18000EE5D END=18000EE6A] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
181. 0 ; DEF: sp+30.4
181. 0 mov    #0x11.4, %var_8A8.4     ; 18000EE5D u=           d=sp+30.4
181. 1 goto   @3                      ; 18000EE65 u=
181. 1
182. 0 ; 1WAY-BLOCK 182 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000EE6A END=18000EF12] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
182. 0 ; USE: ds.2,sp+C8.4,sp+318.1,(GLBLOW,sp+0..C8,sp+CC..318,sp+319..,SHADOW,ARGS,GLBHIGH)
182. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+130.4
182. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
182. 0 mov    &($p_InLoadOrderModuleList_10).8, rcx.8 ; 18000EE75 u=           d=rcx.8
182. 1 mov    #0.1, cf.1              ; 18000EE83 u=           d=cf.1
182. 2 mov    #0.1, of.1              ; 18000EE83 u=           d=of.1
182. 3 setz   (%var_810.4 | (#0x10000.4*xdu.4([ds.2:(xdu.8((%var_5C0.1 & #0xF.1))+&($p_InLoadOrderModuleList_10).8)].1))), #0.4, zf.1 ; 18000EE83 u=ds.2,sp+C8.4,sp+318.1,(GLBLOW,sp+0..C8,sp+CC..318,sp+319..,SHADOW,ARGS,GLBHIGH) d=zf.1
182. 4 setp   (%var_810.4 | (#0x10000.4*xdu.4([ds.2:(xdu.8((%var_5C0.1 & #0xF.1))+&($p_InLoadOrderModuleList_10).8)].1))), #0.4, pf.1 ; 18000EE83 u=ds.2,sp+C8.4,sp+318.1,(GLBLOW,sp+0..C8,sp+CC..318,sp+319..,SHADOW,ARGS,GLBHIGH) d=pf.1
182. 5 sets   (%var_810.4 | (#0x10000.4*xdu.4([ds.2:(xdu.8((%var_5C0.1 & #0xF.1))+&($p_InLoadOrderModuleList_10).8)].1))), sf.1 ; 18000EE83 u=ds.2,sp+C8.4,sp+318.1,(GLBLOW,sp+0..C8,sp+CC..318,sp+319..,SHADOW,ARGS,GLBHIGH) d=sf.1
182. 6 xdu    (%var_810.4 | (#0x10000.4*xdu.4([ds.2:(xdu.8((%var_5C0.1 & #0xF.1))+&($p_InLoadOrderModuleList_10).8)].1))), rax.8 ; 18000EE83 u=ds.2,sp+C8.4,sp+318.1,(GLBLOW,sp+0..C8,sp+CC..318,sp+319..,SHADOW,ARGS,GLBHIGH) d=rax.8
182. 7 or     %var_810.4, (#0x10000.4*xdu.4([ds.2:(xdu.8((%var_5C0.1 & #0xF.1))+&($p_InLoadOrderModuleList_10).8)].1)), %var_7A8.4 ; 18000EE8A u=ds.2,sp+C8.4,sp+318.1,(GLBLOW,sp+0..C8,sp+CC..318,sp+319..,SHADOW,ARGS,GLBHIGH) d=sp+130.4
182. 8 mov    #0x22.4, %var_8A8.4     ; 18000EF05 u=           d=sp+30.4
182. 9 goto   @3                      ; 18000EF0D u=
182. 9
183. 0 ; 1WAY-BLOCK 183 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000EF12 END=18000EFF2] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
183. 0 ; USE: rdi.8,sp+258.8
183. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+60.8
183. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
183. 0 mov    call !__ROL8__<fast:_QWORD %var_680.8,char #0x35.1>.8, rax.8 ; 18000EF6F u=sp+258.8   d=rax.8
183. 1 cfadd  rdi.8, rax.8, cf.1      ; 18000EF73 u=rax.8,rdi.8 d=cf.1
183. 2 ofadd  rdi.8, rax.8, of.1      ; 18000EF73 u=rax.8,rdi.8 d=of.1
183. 3 setz   (rdi.8+rax.8), #0.8, zf.1 ; 18000EF73 u=rax.8,rdi.8 d=zf.1
183. 4 setp   (rdi.8+rax.8), #0.8, pf.1 ; 18000EF73 u=rax.8,rdi.8 d=pf.1
183. 5 sets   (rdi.8+rax.8), sf.1     ; 18000EF73 u=rax.8,rdi.8 d=sf.1
183. 6 add    rdi.8, rax.8, rax.8     ; 18000EF73 u=rax.8,rdi.8 d=rax.8
183. 7 mov    rax.8, %var_878.8       ; 18000EF76 u=rax.8      d=sp+60.8
183. 8 mov    #0x4D.4, %var_8A8.4     ; 18000EFE5 u=           d=sp+30.4
183. 9 goto   @3                      ; 18000EFED u=
183. 9
184. 0 ; 1WAY-BLOCK 184 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000EFF2 END=18000F093] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
184. 0 ; USE: ds.2,sp+E0.4,sp+7C8..7D8,(GLBLOW,sp+0..E0,sp+E4..7C8,sp+7D8..,SHADOW,ARGS,GLBHIGH)
184. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+5D.1,sp+7D8.8
184. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
184. 0 or     %var_110@8.8, %var_110.8, %var_100.8 ; 18000F002 u=sp+7C8..7D8 d=sp+7D8.8
184. 1 mov    #0.1, cf.1              ; 18000F074 u=           d=cf.1
184. 2 mov    #0.1, of.1              ; 18000F074 u=           d=of.1
184. 3 setz   ((%var_7F8.4 >>l #0x14.1) & #0xF.4), #0.4, zf.1 ; 18000F074 u=sp+E0.4    d=zf.1
184. 4 setp   ((%var_7F8.4 >>l #0x14.1) & #0xF.4), #0.4, pf.1 ; 18000F074 u=sp+E0.4    d=pf.1
184. 5 mov    #0.1, sf.1              ; 18000F074 u=           d=sf.1
184. 6 mov    &($p_InLoadOrderModuleList_7).8, rcx.8 ; 18000F077 u=           d=rcx.8
184. 7 xdu    [ds.2:(xdu.8(((%var_7F8.4 >>l #0x14.1) & #0xF.4))+&($p_InLoadOrderModuleList_7).8)].1, rax.8 ; 18000F07E u=ds.2,sp+E0.4,(GLBLOW,sp+0..E0,sp+E4..,SHADOW,ARGS,GLBHIGH) d=rax.8
184. 8 ldx    ds.2, (xdu.8(((%var_7F8.4 >>l #0x14.1) & #0xF.4))+&($p_InLoadOrderModuleList_7).8), %var_87B.1 ; 18000F082 u=ds.2,sp+E0.4,(GLBLOW,sp+0..E0,sp+E4..,SHADOW,ARGS,GLBHIGH) d=sp+5D.1
184. 9 mov    #0xCB.4, %var_8A8.4     ; 18000F086 u=           d=sp+30.4
184.10 goto   @3                      ; 18000F08E u=
184.10
185. 0 ; 1WAY-BLOCK 185 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000F093 END=18000F18C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
185. 0 ; USE: 1802847D8.8
185. 0 ; DEF: rax.8,sp+30.4,sp+460.8
185. 0 ; DNU: rax.8
185. 0 mov    $n0x72.8, rax.8         ; 18000F170 u=1802847D8.8 d=rax.8
185. 1 mov    $n0x72.8, %var_478.8    ; 18000F177 u=1802847D8.8 d=sp+460.8
185. 2 mov    #0x4B.4, %var_8A8.4     ; 18000F17F u=           d=sp+30.4
185. 3 goto   @3                      ; 18000F187 u=
185. 3
186. 0 ; 1WAY-BLOCK 186 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000F18C END=18000F206] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
186. 0 ; USE: sp+2C0.8
186. 0 ; DEF: rax.8,sp+30.4,sp+270.8
186. 0 ; DNU: rax.8
186. 0 mov    %var_618.8, rax.8       ; 18000F1E9 u=sp+2C0.8   d=rax.8
186. 1 mov    %var_618.8, %var_668.8  ; 18000F1F1 u=sp+2C0.8   d=sp+270.8
186. 2 mov    #0x68.4, %var_8A8.4     ; 18000F1F9 u=           d=sp+30.4
186. 3 goto   @3                      ; 18000F201 u=
186. 3
187. 0 ; 1WAY-BLOCK 187 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000F206 END=18000F2DD] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
187. 0 ; USE: sp+170.4
187. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+A0.4
187. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
187. 0 mov    call !__ROL4__<fast:_DWORD %var_768.4,char #0x17.1>.4, eax.4 ; 18000F20D u=sp+170.4   d=eax.4
187. 1 xor    eax.4, #0xFCAB611B.4, eax.4 ; 18000F210 u=eax.4      d=eax.4
187. 2 setz   eax.4, #0.4, zf.1       ; 18000F210 u=eax.4      d=zf.1
187. 3 setp   eax.4, #0.4, pf.1       ; 18000F210 u=eax.4      d=pf.1
187. 4 sets   eax.4, sf.1             ; 18000F210 u=eax.4      d=sf.1
187. 5 cfshl  eax.4, #0xD.1, tt.1     ; 18000F215 u=eax.4      d=tt.1
187. 6 mov    call !__ROL4__<fast:_DWORD eax.4,char #0xD.1>.4, eax.4 ; 18000F215 u=eax.4      d=eax.4
187. 7 mov    tt.1, cf.1              ; 18000F215 u=tt.1       d=cf.1
187. 8 und    of.1                    ; 18000F215 u=           d=of.1
187. 9 xdu    eax.4, rax.8            ; 18000F215 u=eax.4      d=rax^4.4
187.10 mov    eax.4, %var_838.4       ; 18000F25E u=eax.4      d=sp+A0.4
187.11 mov    #0x7A.4, %var_8A8.4     ; 18000F2D0 u=           d=sp+30.4
187.12 goto   @3                      ; 18000F2D8 u=
187.12
188. 0 ; 1WAY-BLOCK 188 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000F2DD END=18000F363] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
188. 0 ; USE: sp+5D0.8
188. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+5D8.8
188. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
188. 0 cfadd  %var_308.8, #0x39B39BF2411BD27C.8, cf.1 ; 18000F346 u=sp+5D0.8   d=cf.1
188. 1 ofadd  %var_308.8, #0x39B39BF2411BD27C.8, of.1 ; 18000F346 u=sp+5D0.8   d=of.1
188. 2 setz   (%var_308.8+#0x39B39BF2411BD27C.8), #0.8, zf.1 ; 18000F346 u=sp+5D0.8   d=zf.1
188. 3 setp   (%var_308.8+#0x39B39BF2411BD27C.8), #0.8, pf.1 ; 18000F346 u=sp+5D0.8   d=pf.1
188. 4 sets   (%var_308.8+#0x39B39BF2411BD27C.8), sf.1 ; 18000F346 u=sp+5D0.8   d=sf.1
188. 5 add    %var_308.8, #0x39B39BF2411BD27C.8, rax.8 ; 18000F346 u=sp+5D0.8   d=rax.8
188. 6 add    %var_308.8, #0x39B39BF2411BD27C.8, %var_300.8 ; 18000F34E u=sp+5D0.8   d=sp+5D8.8
188. 7 mov    #0x78.4, %var_8A8.4     ; 18000F356 u=           d=sp+30.4
188. 8 goto   @3                      ; 18000F35E u=
188. 8
189. 0 ; 1WAY-BLOCK 189 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000F363 END=18000F3D5] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
189. 0 ; USE: sp+1DC.4
189. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+1E0.4
189. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
189. 0 cfadd  %var_6FC.4, #0xF17EC577.4, cf.1 ; 18000F368 u=sp+1DC.4   d=cf.1
189. 1 ofadd  %var_6FC.4, #0xF17EC577.4, of.1 ; 18000F368 u=sp+1DC.4   d=of.1
189. 2 setz   %var_6FC.4, #0xE813A89.4, zf.1 ; 18000F368 u=sp+1DC.4   d=zf.1
189. 3 setp   %var_6FC.4, #0xE813A89.4, pf.1 ; 18000F368 u=sp+1DC.4   d=pf.1
189. 4 sets   (%var_6FC.4-#0xE813A89.4), sf.1 ; 18000F368 u=sp+1DC.4   d=sf.1
189. 5 xdu    (%var_6FC.4-#0xE813A89.4), rax.8 ; 18000F368 u=sp+1DC.4   d=rax.8
189. 6 sub    %var_6FC.4, #0xE813A89.4, %var_6F8.4 ; 18000F36F u=sp+1DC.4   d=sp+1E0.4
189. 7 mov    #0xA3.4, %var_8A8.4     ; 18000F3C8 u=           d=sp+30.4
189. 8 goto   @3                      ; 18000F3D0 u=
189. 8
190. 0 ; 1WAY-BLOCK 190 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000F3D5 END=18000F46A] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
190. 0 ; USE: sp+100.4,sp+224.4
190. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+90.8,sp+D0.4
190. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
190. 0 mov    call !__ROL4__<fast:_DWORD (%var_7D8.4 ^ %var_6B4.4),char #3.1>.4, eax.4 ; 18000F3E3 u=sp+100.4,sp+224.4 d=eax.4
190. 1 cfadd  eax.4, #0x9378C0EB.4, cf.1 ; 18000F3E6 u=eax.4      d=cf.1
190. 2 ofadd  #0x9378C0EB.4, eax.4, of.1 ; 18000F3E6 u=eax.4      d=of.1
190. 3 setz   eax.4, #0x6C873F15.4, zf.1 ; 18000F3E6 u=eax.4      d=zf.1
190. 4 setp   eax.4, #0x6C873F15.4, pf.1 ; 18000F3E6 u=eax.4      d=pf.1
190. 5 sets   (eax.4-#0x6C873F15.4), sf.1 ; 18000F3E6 u=eax.4      d=sf.1
190. 6 sub    eax.4, #0x6C873F15.4, %var_808.4 ; 18000F3EB u=eax.4      d=sp+D0.4
190. 7 xdu    (eax.4-#0x6C873F15.4), rax.8 ; 18000F44E u=eax.4      d=rax.8
190. 8 mov    rax.8, %var_848.8       ; 18000F455 u=rax.8      d=sp+90.8
190. 9 mov    #0xE2.4, %var_8A8.4     ; 18000F45D u=           d=sp+30.4
190.10 goto   @3                      ; 18000F465 u=
190.10
191. 0 ; 1WAY-BLOCK 191 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000F46A END=18000F49C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
191. 0 ; USE: ds.2,sp+1D8.4,sp+670.8,180281E0F.4,(GLBLOW,sp+0..1D8,sp+1DC..670,sp+678..,SHADOW,ARGS,100AE0..180281E0F,180281E13..)
191. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+1DC.4
191. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
191. 0 xor    $dword_180281E0F.4, (%var_700.4 | (#0x10000000.4*xdu.4([ds.2:%var_268.8].1))), eax.4 ; 18000F47F u=ds.2,sp+1D8.4,sp+670.8,180281E0F.4,(GLBLOW,sp+0..1D8,sp+1DC..670,sp+678..,SHADOW,ARGS,100AE0..180281E0F,180281E13..) d=eax.4
191. 1 setz   ($dword_180281E0F.4 ^ (%var_700.4 | (#0x10000000.4*xdu.4([ds.2:%var_268.8].1)))), #0.4, zf.1 ; 18000F47F u=ds.2,sp+1D8.4,sp+670.8,180281E0F.4,(GLBLOW,sp+0..1D8,sp+1DC..670,sp+678..,SHADOW,ARGS,100AE0..180281E0F,180281E13..) d=zf.1
191. 2 setp   ($dword_180281E0F.4 ^ (%var_700.4 | (#0x10000000.4*xdu.4([ds.2:%var_268.8].1)))), #0.4, pf.1 ; 18000F47F u=ds.2,sp+1D8.4,sp+670.8,180281E0F.4,(GLBLOW,sp+0..1D8,sp+1DC..670,sp+678..,SHADOW,ARGS,100AE0..180281E0F,180281E13..) d=pf.1
191. 3 sets   ($dword_180281E0F.4 ^ (%var_700.4 | (#0x10000000.4*xdu.4([ds.2:%var_268.8].1)))), sf.1 ; 18000F47F u=ds.2,sp+1D8.4,sp+670.8,180281E0F.4,(GLBLOW,sp+0..1D8,sp+1DC..670,sp+678..,SHADOW,ARGS,100AE0..180281E0F,180281E13..) d=sf.1
191. 4 cfshl  eax.4, #3.1, tt.1       ; 18000F485 u=eax.4      d=tt.1
191. 5 mov    call !__ROL4__<fast:_DWORD eax.4,char #3.1>.4, eax.4 ; 18000F485 u=eax.4      d=eax.4
191. 6 mov    tt.1, cf.1              ; 18000F485 u=tt.1       d=cf.1
191. 7 und    of.1                    ; 18000F485 u=           d=of.1
191. 8 xdu    eax.4, rax.8            ; 18000F485 u=eax.4      d=rax^4.4
191. 9 mov    eax.4, %var_6FC.4       ; 18000F488 u=eax.4      d=sp+1DC.4
191.10 mov    #0xA2.4, %var_8A8.4     ; 18000F48F u=           d=sp+30.4
191.11 goto   @3                      ; 18000F497 u=
191.11
192. 0 ; 1WAY-BLOCK 192 INBOUNDS: 4 OUTBOUNDS: 193 [START=18000F49C END=18000F4B9] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
192. 0 ; USE: rsp.8,(rax.8,rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH)
192. 0 ; DEF: rdx.8,rcx.8,r8.8,r9.8,(cf.1,zf.1,sf.1,of.1,pf.1,rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
192. 0 add    rsp.8, #0x298.8, r8.8   ; 18000F49C u=rsp.8      d=r8.8
192. 1 mov    #0x33.8, rcx.8          ; 18000F4A4 u=           d=rcx.8
192. 2 mov    #0x5D.8, rdx.8          ; 18000F4A9 u=           d=rdx.8
192. 3 mov    #0x3F.8, r9.8           ; 18000F4AE u=           d=r9.8
192. 4 call   $sub_1800E3F00          ; 18000F4B4 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
192. 4
193. 0 ; 1WAY-BLOCK 193 INBOUNDS: 192 OUTBOUNDS: 3 [START=18000F4B9 END=18000F4DD] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
193. 0 ; USE: rbx.8,sp+298.8
193. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+620.8
193. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
193. 0 mov    call !__ROL8__<fast:_QWORD %var_640.8,char #7.1>.8, rax.8 ; 18000F4C1 u=sp+298.8   d=rax.8
193. 1 cfadd  rbx.8, rax.8, cf.1      ; 18000F4C5 u=rax.8,rbx.8 d=cf.1
193. 2 ofadd  rbx.8, rax.8, of.1      ; 18000F4C5 u=rax.8,rbx.8 d=of.1
193. 3 setz   (rbx.8+rax.8), #0.8, zf.1 ; 18000F4C5 u=rax.8,rbx.8 d=zf.1
193. 4 setp   (rbx.8+rax.8), #0.8, pf.1 ; 18000F4C5 u=rax.8,rbx.8 d=pf.1
193. 5 sets   (rbx.8+rax.8), sf.1     ; 18000F4C5 u=rax.8,rbx.8 d=sf.1
193. 6 add    rbx.8, rax.8, rax.8     ; 18000F4C5 u=rax.8,rbx.8 d=rax.8
193. 7 mov    rax.8, %var_2B8.8       ; 18000F4C8 u=rax.8      d=sp+620.8
193. 8 mov    #0x85.4, %var_8A8.4     ; 18000F4D0 u=           d=sp+30.4
193. 9 goto   @3                      ; 18000F4D8 u=
193. 9
194. 0 ; 1WAY-BLOCK 194 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000F4DD END=18000F56F] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
194. 0 ; USE: sp+5F8.8,180281B8D.8
194. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+600..610
194. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
194. 0 mov    $qword_180281B8D.8, %var_2D8.8 ; 18000F4E4 u=180281B8D.8 d=sp+600.8
194. 1 xor    (%var_2E0.8 ^ $qword_180281B8D.8), #-0x6B99B175547B836D.8, rax.8 ; 18000F4FE u=sp+5F8.8,180281B8D.8 d=rax.8
194. 2 mov    #-0x66CA5D084149E18.8, rcx.8 ; 18000F54D u=           d=rcx.8
194. 3 cfadd  rax.8, #-0x66CA5D084149E18.8, cf.1 ; 18000F557 u=rax.8      d=cf.1
194. 4 ofadd  #-0x66CA5D084149E18.8, rax.8, of.1 ; 18000F557 u=rax.8      d=of.1
194. 5 setz   rax.8, #0x66CA5D084149E18.8, zf.1 ; 18000F557 u=rax.8      d=zf.1
194. 6 setp   rax.8, #0x66CA5D084149E18.8, pf.1 ; 18000F557 u=rax.8      d=pf.1
194. 7 sets   (rax.8-#0x66CA5D084149E18.8), sf.1 ; 18000F557 u=rax.8      d=sf.1
194. 8 sub    rax.8, #0x66CA5D084149E18.8, rax.8 ; 18000F557 u=rax.8      d=rax.8
194. 9 mov    rax.8, %var_2D0.8       ; 18000F55A u=rax.8      d=sp+608.8
194.10 mov    #0x81.4, %var_8A8.4     ; 18000F562 u=           d=sp+30.4
194.11 goto   @3                      ; 18000F56A u=
194.11
195. 0 ; 1WAY-BLOCK 195 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000F56F END=18000F58F] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
195. 0 ; USE: sp+2A8.4
195. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+17C.4
195. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
195. 0 mov    #0.1, cf.1              ; 18000F574 u=           d=cf.1
195. 1 mov    #0.1, of.1              ; 18000F574 u=           d=of.1
195. 2 setz   (%var_630.4 ^ #0x938FE832.4), #0.4, zf.1 ; 18000F574 u=sp+2A8.4   d=zf.1
195. 3 setp   (%var_630.4 ^ #0x938FE832.4), #0.4, pf.1 ; 18000F574 u=sp+2A8.4   d=pf.1
195. 4 sets   bnot(%var_630.4), sf.1  ; 18000F574 u=sp+2A8.4   d=sf.1
195. 5 xdu    (%var_630.4 ^ #0x938FE832.4), rax.8 ; 18000F574 u=sp+2A8.4   d=rax.8
195. 6 xor    %var_630.4, #0x938FE832.4, %var_75C.4 ; 18000F57B u=sp+2A8.4   d=sp+17C.4
195. 7 mov    #0x88.4, %var_8A8.4     ; 18000F582 u=           d=sp+30.4
195. 8 goto   @3                      ; 18000F58A u=
195. 8
196. 0 ; 1WAY-BLOCK 196 INBOUNDS: 4 OUTBOUNDS: 197 [START=18000F58F END=18000F626] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
196. 0 ; USE: rsp.8,sp+608.8,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..608,sp+610..,SHADOW,ARGS,GLBHIGH)
196. 0 ; DEF: cf.1,of.1,rax.16,rcx.8,r8.8,r9.8,sp+2A0.8,(zf.1,sf.1,pf.1,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..2A0,sp+2A8..,RET,SHADOW,ARGS,GLBHIGH)
196. 0 ; DNU: cf.1,of.1
196. 0 mov    call !__ROL8__<fast:_QWORD %var_2D0.8,char #0x39.1>.8, rax.8 ; 18000F5FD u=sp+608.8   d=rax.8
196. 1 cfshl  %var_2D0.8, #0x39.1, cf.1 ; 18000F5FD u=sp+608.8   d=cf.1
196. 2 und    of.1                    ; 18000F5FD u=           d=of.1
196. 3 mov    rax.8, %var_638.8       ; 18000F601 u=rax.8      d=sp+2A0.8
196. 4 add    rsp.8, #0x2A0.8, r9.8   ; 18000F609 u=rsp.8      d=r9.8
196. 5 mov    #0x36.8, rcx.8          ; 18000F611 u=           d=rcx.8
196. 6 mov    #0x52.8, rdx.8          ; 18000F616 u=           d=rdx.8
196. 7 mov    #0x2B.8, r8.8           ; 18000F61B u=           d=r8.8
196. 8 call   $sub_18007FE10          ; 18000F621 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
196. 8
197. 0 ; 1WAY-BLOCK 197 INBOUNDS: 196 OUTBOUNDS: 3 [START=18000F626 END=18000F643] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
197. 0 ; USE: sp+2A0.8
197. 0 ; DEF: rax.8,sp+30.4,sp+610.8
197. 0 ; DNU: rax.8
197. 0 mov    %var_638.8, rax.8       ; 18000F626 u=sp+2A0.8   d=rax.8
197. 1 mov    %var_638.8, %var_2C8.8  ; 18000F62E u=sp+2A0.8   d=sp+610.8
197. 2 mov    #0x82.4, %var_8A8.4     ; 18000F636 u=           d=sp+30.4
197. 3 goto   @3                      ; 18000F63E u=
197. 3
198. 0 ; 1WAY-BLOCK 198 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000F643 END=18000F6B3] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
198. 0 ; DEF: sp+30.4
198. 0 mov    #0xD1.4, %var_8A8.4     ; 18000F6A6 u=           d=sp+30.4
198. 1 goto   @3                      ; 18000F6AE u=
198. 1
199. 0 ; 1WAY-BLOCK 199 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000F6B3 END=18000F75C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
199. 0 ; USE: ds.2,sp+820.8,sp+830.1,(GLBLOW,sp+0..820,sp+828.8,sp+831..,SHADOW,ARGS,GLBHIGH)
199. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+838.8
199. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
199. 0 mov    &($loc_18022725F@1).8, rcx.8 ; 18000F6BE u=           d=rcx.8
199. 1 or     %var_B8.8, xdu.8((#0x100000.4*xdu.4([ds.2:(xdu.8((%var_A8.1 & #0xF.1))+&($loc_18022725F@1).8)].1))), rax.8 ; 18000F6CC u=ds.2,sp+820.8,sp+830.1,(GLBLOW,sp+0..820,sp+828.8,sp+831..,SHADOW,ARGS,GLBHIGH) d=rax.8
199. 2 mov    #0.1, cf.1              ; 18000F6CC u=           d=cf.1
199. 3 mov    #0.1, of.1              ; 18000F6CC u=           d=of.1
199. 4 setz   (%var_B8.8 | xdu.8((#0x100000.4*xdu.4([ds.2:(xdu.8((%var_A8.1 & #0xF.1))+&($loc_18022725F@1).8)].1)))), #0.8, zf.1 ; 18000F6CC u=ds.2,sp+820.8,sp+830.1,(GLBLOW,sp+0..820,sp+828.8,sp+831..,SHADOW,ARGS,GLBHIGH) d=zf.1
199. 5 setp   (%var_B8.8 | xdu.8((#0x100000.4*xdu.4([ds.2:(xdu.8((%var_A8.1 & #0xF.1))+&($loc_18022725F@1).8)].1)))), #0.8, pf.1 ; 18000F6CC u=ds.2,sp+820.8,sp+830.1,(GLBLOW,sp+0..820,sp+828.8,sp+831..,SHADOW,ARGS,GLBHIGH) d=pf.1
199. 6 sets   (%var_B8.8 | xdu.8((#0x100000.4*xdu.4([ds.2:(xdu.8((%var_A8.1 & #0xF.1))+&($loc_18022725F@1).8)].1)))), sf.1 ; 18000F6CC u=ds.2,sp+820.8,sp+830.1,(GLBLOW,sp+0..820,sp+828.8,sp+831..,SHADOW,ARGS,GLBHIGH) d=sf.1
199. 7 or     %var_B8.8, xdu.8((#0x100000.4*xdu.4([ds.2:(xdu.8((%var_A8.1 & #0xF.1))+&($loc_18022725F@1).8)].1))), %var_A0.8 ; 18000F6D4 u=ds.2,sp+820.8,sp+830.1,(GLBLOW,sp+0..820,sp+828.8,sp+831..,SHADOW,ARGS,GLBHIGH) d=sp+838.8
199. 8 mov    #0xE5.4, %var_8A8.4     ; 18000F74F u=           d=sp+30.4
199. 9 goto   @3                      ; 18000F757 u=
199. 9
200. 0 ; 1WAY-BLOCK 200 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000F75C END=18000F858] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
200. 0 ; USE: sp+1E8.4,sp+780.8
200. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+A8.4,sp+788.8
200. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
200. 0 mov    #0.1, cf.1              ; 18000F7C7 u=           d=cf.1
200. 1 mov    #0.1, of.1              ; 18000F7C7 u=           d=of.1
200. 2 setz   (%var_6F0.4 ^ #0xDC994C41.4), #0.4, zf.1 ; 18000F7C7 u=sp+1E8.4   d=zf.1
200. 3 setp   (%var_6F0.4 ^ #0xDC994C41.4), #0.4, pf.1 ; 18000F7C7 u=sp+1E8.4   d=pf.1
200. 4 sets   bnot(%var_6F0.4), sf.1  ; 18000F7C7 u=sp+1E8.4   d=sf.1
200. 5 xdu    (%var_6F0.4 ^ #0xDC994C41.4), rax.8 ; 18000F7C7 u=sp+1E8.4   d=rax.8
200. 6 mov    %var_158.8, rcx.8       ; 18000F7CE u=sp+780.8   d=rcx.8
200. 7 mov    %var_158.8, %var_150.8  ; 18000F7D6 u=sp+780.8   d=sp+788.8
200. 8 xor    %var_6F0.4, #0xDC994C41.4, %var_830.4 ; 18000F7DE u=sp+1E8.4   d=sp+A8.4
200. 9 mov    #0xBF.4, %var_8A8.4     ; 18000F84B u=           d=sp+30.4
200.10 goto   @3                      ; 18000F853 u=
200.10
201. 0 ; 1WAY-BLOCK 201 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000F858 END=18000F88E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
201. 0 ; USE: ds.2,sp+7F0.9,(GLBLOW,sp+0..7F0,sp+7F9..,SHADOW,ARGS,GLBHIGH)
201. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+800.8
201. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
201. 0 mov    &($p_InLoadOrderModuleList_7).8, rcx.8 ; 18000F863 u=           d=rcx.8
201. 1 or     %var_E8.8, xdu.8((#0x1000.4*xdu.4([ds.2:(xdu.8((%var_E0.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1))), rax.8 ; 18000F871 u=ds.2,sp+7F0.9,(GLBLOW,sp+0..7F0,sp+7F9..,SHADOW,ARGS,GLBHIGH) d=rax.8
201. 2 mov    #0.1, cf.1              ; 18000F871 u=           d=cf.1
201. 3 mov    #0.1, of.1              ; 18000F871 u=           d=of.1
201. 4 setz   (%var_E8.8 | xdu.8((#0x1000.4*xdu.4([ds.2:(xdu.8((%var_E0.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1)))), #0.8, zf.1 ; 18000F871 u=ds.2,sp+7F0.9,(GLBLOW,sp+0..7F0,sp+7F9..,SHADOW,ARGS,GLBHIGH) d=zf.1
201. 5 setp   (%var_E8.8 | xdu.8((#0x1000.4*xdu.4([ds.2:(xdu.8((%var_E0.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1)))), #0.8, pf.1 ; 18000F871 u=ds.2,sp+7F0.9,(GLBLOW,sp+0..7F0,sp+7F9..,SHADOW,ARGS,GLBHIGH) d=pf.1
201. 6 sets   (%var_E8.8 | xdu.8((#0x1000.4*xdu.4([ds.2:(xdu.8((%var_E0.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1)))), sf.1 ; 18000F871 u=ds.2,sp+7F0.9,(GLBLOW,sp+0..7F0,sp+7F9..,SHADOW,ARGS,GLBHIGH) d=sf.1
201. 7 or     %var_E8.8, xdu.8((#0x1000.4*xdu.4([ds.2:(xdu.8((%var_E0.1 & #0xF.1))+&($p_InLoadOrderModuleList_7).8)].1))), %var_D8.8 ; 18000F879 u=ds.2,sp+7F0.9,(GLBLOW,sp+0..7F0,sp+7F9..,SHADOW,ARGS,GLBHIGH) d=sp+800.8
201. 8 mov    #0xCE.4, %var_8A8.4     ; 18000F881 u=           d=sp+30.4
201. 9 goto   @3                      ; 18000F889 u=
201. 9
202. 0 ; 1WAY-BLOCK 202 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000F88E END=18000F8AE] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
202. 0 ; USE: r12.8,sp+778.8
202. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+780.8
202. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
202. 0 xor    r12.8, %var_160.8, rax.8 ; 18000F896 u=r12.8,sp+778.8 d=rax.8
202. 1 mov    #0.1, cf.1              ; 18000F896 u=           d=cf.1
202. 2 mov    #0.1, of.1              ; 18000F896 u=           d=of.1
202. 3 setz   (r12.8 ^ %var_160.8), #0.8, zf.1 ; 18000F896 u=r12.8,sp+778.8 d=zf.1
202. 4 setp   (r12.8 ^ %var_160.8), #0.8, pf.1 ; 18000F896 u=r12.8,sp+778.8 d=pf.1
202. 5 sets   (r12.8 ^ %var_160.8), sf.1 ; 18000F896 u=r12.8,sp+778.8 d=sf.1
202. 6 xor    r12.8, %var_160.8, %var_158.8 ; 18000F899 u=r12.8,sp+778.8 d=sp+780.8
202. 7 mov    #0xBD.4, %var_8A8.4     ; 18000F8A1 u=           d=sp+30.4
202. 8 goto   @3                      ; 18000F8A9 u=
202. 8
203. 0 ; 1WAY-BLOCK 203 INBOUNDS: 4 OUTBOUNDS: 204 [START=18000F8AE END=18000F933] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
203. 0 ; USE: rsp.8,sp+220.4,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..220,sp+224..,SHADOW,ARGS,GLBHIGH)
203. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,sp+C0.4,(r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..C0,sp+C4..,RET,SHADOW,ARGS,GLBHIGH)
203. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
203. 0 mov    #0.1, cf.1              ; 18000F8B3 u=           d=cf.1
203. 1 mov    #0.1, of.1              ; 18000F8B3 u=           d=of.1
203. 2 setz   (%var_6B8.4 ^ #0xBE343DD0.4), #0.4, zf.1 ; 18000F8B3 u=sp+220.4   d=zf.1
203. 3 setp   (%var_6B8.4 ^ #0xBE343DD0.4), #0.4, pf.1 ; 18000F8B3 u=sp+220.4   d=pf.1
203. 4 sets   bnot(%var_6B8.4), sf.1  ; 18000F8B3 u=sp+220.4   d=sf.1
203. 5 xdu    (%var_6B8.4 ^ #0xBE343DD0.4), rax.8 ; 18000F8B3 u=sp+220.4   d=rax.8
203. 6 xor    %var_6B8.4, #0xBE343DD0.4, %var_818.4 ; 18000F90E u=sp+220.4   d=sp+C0.4
203. 7 add    rsp.8, #0xC0.8, rdx.8   ; 18000F915 u=rsp.8      d=rdx.8
203. 8 mov    #3.8, rcx.8             ; 18000F91D u=           d=rcx.8
203. 9 mov    #0x18.8, r8.8           ; 18000F922 u=           d=r8.8
203.10 mov    #0x17.8, r9.8           ; 18000F928 u=           d=r9.8
203.11 call   $sub_1801E63E0          ; 18000F92E u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
203.11
204. 0 ; 1WAY-BLOCK 204 INBOUNDS: 203 OUTBOUNDS: 3 [START=18000F933 END=18000F94E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
204. 0 ; USE: sp+C0.4
204. 0 ; DEF: rax.8,sp+30.4,sp+224.4
204. 0 ; DNU: rax.8
204. 0 xdu    %var_818.4, rax.8       ; 18000F933 u=sp+C0.4    d=rax.8
204. 1 mov    %var_818.4, %var_6B4.4  ; 18000F93A u=sp+C0.4    d=sp+224.4
204. 2 mov    #0xE1.4, %var_8A8.4     ; 18000F941 u=           d=sp+30.4
204. 3 goto   @3                      ; 18000F949 u=
204. 3
205. 0 ; 1WAY-BLOCK 205 INBOUNDS: 4 OUTBOUNDS: 206 [START=18000F94E END=18000FA26] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
205. 0 ; USE: rsp.8,(rax.8,rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH)
205. 0 ; DEF: rdx.8,rcx.8,r8.8,r9.8,sp+38.1,(cf.1,zf.1,sf.1,of.1,pf.1,rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm4.16,xmm5.16,GLBLOW,sp+0..38,sp+39..,RET,SHADOW,ARGS,GLBHIGH)
205. 0 mov    #0.1, %var_8A0.1        ; 18000F94E u=           d=sp+38.1
205. 1 add    rsp.8, #0x38.8, r9.8    ; 18000FA0C u=rsp.8      d=r9.8
205. 2 mov    #0x31.8, rcx.8          ; 18000FA11 u=           d=rcx.8
205. 3 mov    #0x12.8, rdx.8          ; 18000FA16 u=           d=rdx.8
205. 4 mov    #0x64.8, r8.8           ; 18000FA1B u=           d=r8.8
205. 5 call   $sub_1801C72D0          ; 18000FA21 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm4.16,xmm5.16,ALLMEM)
205. 5
206. 0 ; 1WAY-BLOCK 206 INBOUNDS: 205 OUTBOUNDS: 3 [START=18000FA26 END=18000FA3E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
206. 0 ; USE: sp+38.1
206. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+3D.1
206. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
206. 0 xdu    %var_8A0.1, rax.8       ; 18000FA26 u=sp+38.1    d=rax.8
206. 1 cfadd  %var_8A0.1, #0x3A.1, cf.1 ; 18000FA2B u=sp+38.1    d=cf.1
206. 2 ofadd  #0x3A.1, %var_8A0.1, of.1 ; 18000FA2B u=sp+38.1    d=of.1
206. 3 setz   (%var_8A0.1+#0x3A.1), #0.1, zf.1 ; 18000FA2B u=sp+38.1    d=zf.1
206. 4 setp   (%var_8A0.1+#0x3A.1), #0.1, pf.1 ; 18000FA2B u=sp+38.1    d=pf.1
206. 5 sets   (%var_8A0.1+#0x3A.1), sf.1 ; 18000FA2B u=sp+38.1    d=sf.1
206. 6 add    %var_8A0.1, #0x3A.1, al.1 ; 18000FA2B u=sp+38.1    d=al.1
206. 7 add    %var_8A0.1, #0x3A.1, %var_89B.1 ; 18000FA2D u=sp+38.1    d=sp+3D.1
206. 8 mov    #0xDC.4, %var_8A8.4     ; 18000FA31 u=           d=sp+30.4
206. 9 goto   @3                      ; 18000FA39 u=
206. 9
207. 0 ; 1WAY-BLOCK 207 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000FA3E END=18000FA4B] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
207. 0 ; DEF: sp+30.4
207. 0 mov    #0xDB.4, %var_8A8.4     ; 18000FA3E u=           d=sp+30.4
207. 1 goto   @3                      ; 18000FA46 u=
207. 1
208. 0 ; 1WAY-BLOCK 208 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000FA4B END=18000FA6E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
208. 0 ; USE: rsi.8,r15.8,sp+618.8
208. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+298.8
208. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
208. 0 xor    r15.8, (rsi.8+%var_2C0.8), rax.8 ; 18000FA56 u=rsi.8,r15.8,sp+618.8 d=rax.8
208. 1 mov    #0.1, cf.1              ; 18000FA56 u=           d=cf.1
208. 2 mov    #0.1, of.1              ; 18000FA56 u=           d=of.1
208. 3 setz   (r15.8 ^ (rsi.8+%var_2C0.8)), #0.8, zf.1 ; 18000FA56 u=rsi.8,r15.8,sp+618.8 d=zf.1
208. 4 setp   (r15.8 ^ (rsi.8+%var_2C0.8)), #0.8, pf.1 ; 18000FA56 u=rsi.8,r15.8,sp+618.8 d=pf.1
208. 5 sets   (r15.8 ^ (rsi.8+%var_2C0.8)), sf.1 ; 18000FA56 u=rsi.8,r15.8,sp+618.8 d=sf.1
208. 6 xor    r15.8, (rsi.8+%var_2C0.8), %var_640.8 ; 18000FA59 u=rsi.8,r15.8,sp+618.8 d=sp+298.8
208. 7 mov    #0x84.4, %var_8A8.4     ; 18000FA61 u=           d=sp+30.4
208. 8 goto   @3                      ; 18000FA69 u=
208. 8
209. 0 ; 1WAY-BLOCK 209 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000FA6E END=18000FA9F] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
209. 0 ; USE: ds.2,sp+2D8.8,(GLBLOW,sp+0..2D8,sp+2E0..,SHADOW,ARGS,GLBHIGH)
209. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+1F4.8
209. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
209. 0 ldx    ds.2, %var_600.8, eax.4 ; 18000FA76 u=ds.2,sp+2D8.8,(GLBLOW,sp+0..2D8,sp+2E0..,SHADOW,ARGS,GLBHIGH) d=eax.4
209. 1 xdu    (#0xCC9E2D51.4*[ds.2:%var_600.8].4), rcx.8 ; 18000FA78 u=ds.2,sp+2D8.8,(GLBLOW,sp+0..2D8,sp+2E0..,SHADOW,ARGS,GLBHIGH) d=rcx.8
209. 2 mul    #0xCC9E2D51.4, [ds.2:%var_600.8].4, %var_6E4.4 ; 18000FA7E split4 u=ds.2,sp+2D8.8,(GLBLOW,sp+0..2D8,sp+2E0..,SHADOW,ARGS,GLBHIGH) d=sp+1F4.4
209. 3 setnz  high.4((#0x16A88000.8*xds.8(eax.4))), #0.4, cf.1 ; 18000FA85 u=eax.4      d=cf.1
209. 4 setnz  high.4((#0x16A88000.8*xds.8(eax.4))), #0.4, of.1 ; 18000FA85 u=eax.4      d=of.1
209. 5 und    zf.1                    ; 18000FA85 u=           d=zf.1
209. 6 und    sf.1                    ; 18000FA85 u=           d=sf.1
209. 7 und    pf.1                    ; 18000FA85 u=           d=pf.1
209. 8 xdu    (#0x16A88000.4*eax.4), rax.8 ; 18000FA85 u=eax.4      d=rax.8
209. 9 mov    eax.4, %var_6E0.4       ; 18000FA8B u=eax.4      d=sp+1F8.4
209.10 mov    #0xD2.4, %var_8A8.4     ; 18000FA92 u=           d=sp+30.4
209.11 goto   @3                      ; 18000FA9A u=
209.11
210. 0 ; 1WAY-BLOCK 210 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000FA9F END=18000FAC7] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
210. 0 ; USE: ds.2,sp+3D.1,sp+5E.1,(GLBLOW,sp+0..3D,sp+3E..5E,sp+5F..,SHADOW,ARGS,GLBHIGH)
210. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,sp+30.4,sp+5F.1
210. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rdx.8,rcx.8
210. 0 xdu    (%var_89B.1 & #0xF.1), rax.8 ; 18000FAA4 u=sp+3D.1    d=rax.8
210. 1 mov    &($p_InLoadOrderModuleList_8).8, rcx.8 ; 18000FAA7 u=           d=rcx.8
210. 2 xdu    %var_87A.1, rdx.8       ; 18000FAAE u=sp+5E.1    d=rdx.8
210. 3 or     [ds.2:(rax.8+&($p_InLoadOrderModuleList_8).8)].1, %var_87A.1, dl.1 ; 18000FAB3 u=rax.8,ds.2,sp+5E.1,(GLBLOW,sp+0..5E,sp+5F..,SHADOW,ARGS,GLBHIGH) d=dl.1
210. 4 mov    #0.1, cf.1              ; 18000FAB3 u=           d=cf.1
210. 5 mov    #0.1, of.1              ; 18000FAB3 u=           d=of.1
210. 6 setz   ([ds.2:(rax.8+&($p_InLoadOrderModuleList_8).8)].1 | %var_87A.1), #0.1, zf.1 ; 18000FAB3 u=rax.8,ds.2,sp+5E.1,(GLBLOW,sp+0..5E,sp+5F..,SHADOW,ARGS,GLBHIGH) d=zf.1
210. 7 setp   ([ds.2:(rax.8+&($p_InLoadOrderModuleList_8).8)].1 | %var_87A.1), #0.1, pf.1 ; 18000FAB3 u=rax.8,ds.2,sp+5E.1,(GLBLOW,sp+0..5E,sp+5F..,SHADOW,ARGS,GLBHIGH) d=pf.1
210. 8 sets   ([ds.2:(rax.8+&($p_InLoadOrderModuleList_8).8)].1 | %var_87A.1), sf.1 ; 18000FAB3 u=rax.8,ds.2,sp+5E.1,(GLBLOW,sp+0..5E,sp+5F..,SHADOW,ARGS,GLBHIGH) d=sf.1
210. 9 or     [ds.2:(rax.8+&($p_InLoadOrderModuleList_8).8)].1, %var_87A.1, %var_879.1 ; 18000FAB6 u=rax.8,ds.2,sp+5E.1,(GLBLOW,sp+0..5E,sp+5F..,SHADOW,ARGS,GLBHIGH) d=sp+5F.1
210.10 mov    #0xDE.4, %var_8A8.4     ; 18000FABA u=           d=sp+30.4
210.11 goto   @3                      ; 18000FAC2 u=
210.11
211. 0 ; 1WAY-BLOCK 211 INBOUNDS: 4 OUTBOUNDS: 212 [START=18000FAC7 END=18000FAE1] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
211. 0 ; USE: sp+74.4,(rax.8,rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..74,sp+78..,SHADOW,ARGS,GLBHIGH)
211. 0 ; DEF: rdx.8,rcx.8,r8.8,r9.8,(cf.1,zf.1,sf.1,of.1,pf.1,rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
211. 0 xdu    %var_864.4, r8.8        ; 18000FAC7 u=sp+74.4    d=r8.8
211. 1 mov    #0x2A.8, rcx.8          ; 18000FACC u=           d=rcx.8
211. 2 mov    #0x5C.8, rdx.8          ; 18000FAD1 u=           d=rdx.8
211. 3 mov    #0xF.8, r9.8            ; 18000FAD6 u=           d=r9.8
211. 4 call   $sub_180143A00          ; 18000FADC u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
211. 4
212. 0 ; 1WAY-BLOCK 212 INBOUNDS: 211 OUTBOUNDS: 3 [START=18000FAE1 END=18000FB57] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
212. 0 ; USE: rax.8,ds.2,(GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH)
212. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+2D0.8,sp+798..7A8
212. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
212. 0 ldx    ds.2, rax.8, %var_608.8 ; 18000FAE4 u=rax.8,ds.2,(GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=sp+2D0.8
212. 1 add    rax.8, #0x10.8, rcx.8   ; 18000FAEC u=rax.8      d=rcx.8
212. 2 add    rax.8, #0x10.8, %var_140.8 ; 18000FAF0 u=rax.8      d=sp+798.8
212. 3 ldx    ds.2, (rax.8+#0x10.8), rax.8 ; 18000FAF8 u=rax.8,ds.2,(GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=rax.8
212. 4 cfadd  rax.8, #0x2C.8, cf.1    ; 18000FB3E u=rax.8      d=cf.1
212. 5 ofadd  #0x2C.8, rax.8, of.1    ; 18000FB3E u=rax.8      d=of.1
212. 6 setz   (rax.8+#0x2C.8), #0.8, zf.1 ; 18000FB3E u=rax.8      d=zf.1
212. 7 setp   (rax.8+#0x2C.8), #0.8, pf.1 ; 18000FB3E u=rax.8      d=pf.1
212. 8 sets   (rax.8+#0x2C.8), sf.1   ; 18000FB3E u=rax.8      d=sf.1
212. 9 add    rax.8, #0x2C.8, rax.8   ; 18000FB3E u=rax.8      d=rax.8
212.10 mov    rax.8, %var_138.8       ; 18000FB42 u=rax.8      d=sp+7A0.8
212.11 mov    #0xC2.4, %var_8A8.4     ; 18000FB4A u=           d=sp+30.4
212.12 goto   @3                      ; 18000FB52 u=
212.12
213. 0 ; 1WAY-BLOCK 213 INBOUNDS: 4 OUTBOUNDS: 214 [START=18000FB57 END=18000FB95] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
213. 0 ; USE: rsp.8,r13.8,sp+580.8,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..580,sp+588..,SHADOW,ARGS,GLBHIGH)
213. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,sp+268.8,(r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..268,sp+270..,RET,SHADOW,ARGS,GLBHIGH)
213. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
213. 0 xor    r13.8, %var_358.8, rax.8 ; 18000FB5F u=r13.8,sp+580.8 d=rax.8
213. 1 cfadd  (r13.8 ^ %var_358.8), #-0x238D1C151101C288.8, cf.1 ; 18000FB6C u=r13.8,sp+580.8 d=cf.1
213. 2 ofadd  (r13.8 ^ %var_358.8), #-0x238D1C151101C288.8, of.1 ; 18000FB6C u=r13.8,sp+580.8 d=of.1
213. 3 setz   (r13.8 ^ %var_358.8), #0x238D1C151101C288.8, zf.1 ; 18000FB6C u=r13.8,sp+580.8 d=zf.1
213. 4 setp   (r13.8 ^ %var_358.8), #0x238D1C151101C288.8, pf.1 ; 18000FB6C u=r13.8,sp+580.8 d=pf.1
213. 5 sets   ((r13.8 ^ %var_358.8)-#0x238D1C151101C288.8), sf.1 ; 18000FB6C u=r13.8,sp+580.8 d=sf.1
213. 6 sub    (r13.8 ^ %var_358.8), #0x238D1C151101C288.8, %var_670.8 ; 18000FB6F u=r13.8,sp+580.8 d=sp+268.8
213. 7 add    rsp.8, #0x268.8, rcx.8  ; 18000FB77 u=rsp.8      d=rcx.8
213. 8 mov    #0x51.8, rdx.8          ; 18000FB7F u=           d=rdx.8
213. 9 mov    #5.8, r8.8              ; 18000FB84 u=           d=r8.8
213.10 mov    #0x3C.8, r9.8           ; 18000FB8A u=           d=r9.8
213.11 call   $sub_18011CB90          ; 18000FB90 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
213.11
214. 0 ; 1WAY-BLOCK 214 INBOUNDS: 213 OUTBOUNDS: 3 [START=18000FB95 END=18000FBB2] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
214. 0 ; USE: sp+268.8
214. 0 ; DEF: rax.8,sp+30.4,sp+2C0.8
214. 0 ; DNU: rax.8
214. 0 mov    %var_670.8, rax.8       ; 18000FB95 u=sp+268.8   d=rax.8
214. 1 mov    %var_670.8, %var_618.8  ; 18000FB9D u=sp+268.8   d=sp+2C0.8
214. 2 mov    #0x67.4, %var_8A8.4     ; 18000FBA5 u=           d=sp+30.4
214. 3 goto   @3                      ; 18000FBAD u=
214. 3
215. 0 ; 1WAY-BLOCK 215 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000FBB2 END=18000FBD5] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
215. 0 ; USE: sp+17C.4
215. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+180.4
215. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
215. 0 setz   (%var_75C.4+#0x3868C294.4), #0.4, zf.1 ; 18000FBB7 u=sp+17C.4   d=zf.1
215. 1 setp   (%var_75C.4+#0x3868C294.4), #0.4, pf.1 ; 18000FBB7 u=sp+17C.4   d=pf.1
215. 2 sets   (%var_75C.4+#0x3868C294.4), sf.1 ; 18000FBB7 u=sp+17C.4   d=sf.1
215. 3 mov    call !__ROL4__<fast:_DWORD (%var_75C.4+#0x3868C294.4),char #0x1D.1>.4, eax.4 ; 18000FBBE u=sp+17C.4   d=eax.4
215. 4 cfshl  (%var_75C.4+#0x3868C294.4), #0x1D.1, cf.1 ; 18000FBBE u=sp+17C.4   d=cf.1
215. 5 und    of.1                    ; 18000FBBE u=           d=of.1
215. 6 xdu    eax.4, rax.8            ; 18000FBBE u=eax.4      d=rax^4.4
215. 7 mov    eax.4, %var_758.4       ; 18000FBC1 u=eax.4      d=sp+180.4
215. 8 mov    #0x89.4, %var_8A8.4     ; 18000FBC8 u=           d=sp+30.4
215. 9 goto   @3                      ; 18000FBD0 u=
215. 9
216. 0 ; 1WAY-BLOCK 216 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000FBD5 END=18000FC4F] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
216. 0 ; USE: sp+2C8.8,sp+598.8
216. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+5A0.8
216. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
216. 0 mov    call !__ROL8__<fast:_QWORD %var_340.8,char #0xC.1>.8, rax.8 ; 18000FBDD u=sp+598.8   d=rax.8
216. 1 xor    %var_610.8, rax.8, rax.8 ; 18000FBE1 u=rax.8,sp+2C8.8 d=rax.8
216. 2 setz   rax.8, #0.8, zf.1       ; 18000FBE1 u=rax.8      d=zf.1
216. 3 setp   rax.8, #0.8, pf.1       ; 18000FBE1 u=rax.8      d=pf.1
216. 4 sets   rax.8, sf.1             ; 18000FBE1 u=rax.8      d=sf.1
216. 5 cfshl  rax.8, #0x21.1, tt.1    ; 18000FC36 u=rax.8      d=tt.1
216. 6 mov    call !__ROL8__<fast:_QWORD rax.8,char #0x21.1>.8, rax.8 ; 18000FC36 u=rax.8      d=rax.8
216. 7 mov    tt.1, cf.1              ; 18000FC36 u=tt.1       d=cf.1
216. 8 und    of.1                    ; 18000FC36 u=           d=of.1
216. 9 mov    rax.8, %var_338.8       ; 18000FC3A u=rax.8      d=sp+5A0.8
216.10 mov    #0x70.4, %var_8A8.4     ; 18000FC42 u=           d=sp+30.4
216.11 goto   @3                      ; 18000FC4A u=
216.11
217. 0 ; 1WAY-BLOCK 217 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000FC4F END=18000FC9B] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
217. 0 ; USE: ds.2,sp+68.8,sp+6D0..6E0,(GLBLOW,sp+0..68,sp+70..6D0,sp+6E0..,SHADOW,ARGS,GLBHIGH)
217. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+6E0..6F8
217. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
217. 0 or     %var_208.8, (#0x100000000000000.8*xdu.8([ds.2:%var_200.8].1)), %var_1F8.8 ; 18000FC66 u=ds.2,sp+6D0..6E0,(GLBLOW,sp+0..6D0,sp+6E0..,SHADOW,ARGS,GLBHIGH) d=sp+6E0.8
217. 1 shr    %var_870.8, #8.1, rcx.8 ; 18000FC76 u=sp+68.8    d=rcx.8
217. 2 shr    %var_870.8, #8.1, %var_1F0.8 ; 18000FC7A u=sp+68.8    d=sp+6E8.8
217. 3 cfshr  %var_870.8, #0xC.1, cf.1 ; 18000FC82 u=sp+68.8    d=cf.1
217. 4 shr    %var_870.8, #0xC.1, rax.8 ; 18000FC82 u=sp+68.8    d=rax.8
217. 5 und    of.1                    ; 18000FC82 u=           d=of.1
217. 6 setz   (%var_870.8 >>l #0xC.1), #0.8, zf.1 ; 18000FC82 u=sp+68.8    d=zf.1
217. 7 setp   (%var_870.8 >>l #0xC.1), #0.8, pf.1 ; 18000FC82 u=sp+68.8    d=pf.1
217. 8 mov    #0.1, sf.1              ; 18000FC82 u=           d=sf.1
217. 9 shr    %var_870.8, #0xC.1, %var_1E8.8 ; 18000FC86 u=sp+68.8    d=sp+6F0.8
217.10 mov    #0xB0.4, %var_8A8.4     ; 18000FC8E u=           d=sp+30.4
217.11 goto   @3                      ; 18000FC96 u=
217.11
218. 0 ; 1WAY-BLOCK 218 INBOUNDS: 4 OUTBOUNDS: 219 [START=18000FC9B END=18000FCC4] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
218. 0 ; USE: sp+1EC.4,sp+790.8,(rax.8,rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..1EC,sp+1F0..790,sp+798..,SHADOW,ARGS,GLBHIGH)
218. 0 ; DEF: rdx.8,rcx.8,r8.8,r9.8,sp+20.8,(cf.1,zf.1,sf.1,of.1,pf.1,rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..20,sp+28..,RET,SHADOW,ARGS,GLBHIGH)
218. 0 xdu    %var_6EC.4, r8.8        ; 18000FC9B u=sp+1EC.4   d=r8.8
218. 1 mov    %var_148.8, rcx.8       ; 18000FCA3 u=sp+790.8   d=rcx.8
218. 2 mov    #0x32.8, %var_8B8.8     ; 18000FCAB u=           d=sp+20.8
218. 3 mov    #0x28.8, rdx.8          ; 18000FCB4 u=           d=rdx.8
218. 4 mov    #6.8, r9.8              ; 18000FCB9 u=           d=r9.8
218. 5 call   $sub_180096B30          ; 18000FCBF u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
218. 5
219. 0 ; 1WAY-BLOCK 219 INBOUNDS: 218 OUTBOUNDS: 3 [START=18000FCC4 END=18000FCD1] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
219. 0 ; DEF: sp+30.4
219. 0 mov    #0x11.4, %var_8A8.4     ; 18000FCC4 u=           d=sp+30.4
219. 1 goto   @3                      ; 18000FCCC u=
219. 1
220. 0 ; 1WAY-BLOCK 220 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000FCD1 END=18000FD6E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
220. 0 ; USE: ds.2,sp+40.8,(GLBLOW,sp+0..40,sp+48..,SHADOW,ARGS,GLBHIGH)
220. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+54.1,sp+370.8
220. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
220. 0 shr    %var_898.8, #0x30.1, %var_568.8 ; 18000FCDD u=sp+40.8    d=sp+370.8
220. 1 mov    #0.1, cf.1              ; 18000FCE9 u=           d=cf.1
220. 2 mov    #0.1, of.1              ; 18000FCE9 u=           d=of.1
220. 3 setz   (low.4((%var_898.8 >>l #0x34.1)) & #0xF.4), #0.4, zf.1 ; 18000FCE9 u=sp+40.8    d=zf.1
220. 4 setp   (low.4((%var_898.8 >>l #0x34.1)) & #0xF.4), #0.4, pf.1 ; 18000FCE9 u=sp+40.8    d=pf.1
220. 5 mov    #0.1, sf.1              ; 18000FCE9 u=           d=sf.1
220. 6 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18000FD52 u=           d=rcx.8
220. 7 xdu    [ds.2:(((%var_898.8 >>l #0x34.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8)].1, rax.8 ; 18000FD59 u=ds.2,sp+40.8,(GLBLOW,sp+0..40,sp+48..,SHADOW,ARGS,GLBHIGH) d=rax.8
220. 8 ldx    ds.2, (((%var_898.8 >>l #0x34.1) & #0xF.8)+&($p_InLoadOrderModuleList_5).8), %var_884.1 ; 18000FD5D u=ds.2,sp+40.8,(GLBLOW,sp+0..40,sp+48..,SHADOW,ARGS,GLBHIGH) d=sp+54.1
220. 9 mov    #0x32.4, %var_8A8.4     ; 18000FD61 u=           d=sp+30.4
220.10 goto   @3                      ; 18000FD69 u=
220.10
221. 0 ; 1WAY-BLOCK 221 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000FD6E END=18000FD9E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
221. 0 ; USE: sp+154.8
221. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+160.4
221. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
221. 0 mov    call !__ROL4__<fast:_DWORD %var_784.4,char #0x11.1>.4, eax.4 ; 18000FD75 u=sp+154.4   d=eax.4
221. 1 xor    (%var_780.4 ^ (eax.4+#0x34B92CEE.4)), #0x64.4, eax.4 ; 18000FD84 u=eax.4,sp+158.4 d=eax.4
221. 2 setz   eax.4, #0.4, zf.1       ; 18000FD84 u=eax.4      d=zf.1
221. 3 setp   eax.4, #0.4, pf.1       ; 18000FD84 u=eax.4      d=pf.1
221. 4 sets   eax.4, sf.1             ; 18000FD84 u=eax.4      d=sf.1
221. 5 cfshl  eax.4, #0x14.1, tt.1    ; 18000FD87 u=eax.4      d=tt.1
221. 6 mov    call !__ROL4__<fast:_DWORD eax.4,char #0x14.1>.4, eax.4 ; 18000FD87 u=eax.4      d=eax.4
221. 7 mov    tt.1, cf.1              ; 18000FD87 u=tt.1       d=cf.1
221. 8 und    of.1                    ; 18000FD87 u=           d=of.1
221. 9 xdu    eax.4, rax.8            ; 18000FD87 u=eax.4      d=rax^4.4
221.10 mov    eax.4, %var_778.4       ; 18000FD8A u=eax.4      d=sp+160.4
221.11 mov    #0x4A.4, %var_8A8.4     ; 18000FD91 u=           d=sp+30.4
221.12 goto   @3                      ; 18000FD99 u=
221.12
222. 0 ; 1WAY-BLOCK 222 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000FD9E END=18000FE0E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
222. 0 ; USE: rsi.8,r15.8,sp+5E0.8
222. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+5E8.8
222. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
222. 0 xor    r15.8, (rsi.8+%var_2F8.8), rax.8 ; 18000FDF6 u=rsi.8,r15.8,sp+5E0.8 d=rax.8
222. 1 mov    #0.1, cf.1              ; 18000FDF6 u=           d=cf.1
222. 2 mov    #0.1, of.1              ; 18000FDF6 u=           d=of.1
222. 3 setz   (r15.8 ^ (rsi.8+%var_2F8.8)), #0.8, zf.1 ; 18000FDF6 u=rsi.8,r15.8,sp+5E0.8 d=zf.1
222. 4 setp   (r15.8 ^ (rsi.8+%var_2F8.8)), #0.8, pf.1 ; 18000FDF6 u=rsi.8,r15.8,sp+5E0.8 d=pf.1
222. 5 sets   (r15.8 ^ (rsi.8+%var_2F8.8)), sf.1 ; 18000FDF6 u=rsi.8,r15.8,sp+5E0.8 d=sf.1
222. 6 xor    r15.8, (rsi.8+%var_2F8.8), %var_2F0.8 ; 18000FDF9 u=rsi.8,r15.8,sp+5E0.8 d=sp+5E8.8
222. 7 mov    #0x7C.4, %var_8A8.4     ; 18000FE01 u=           d=sp+30.4
222. 8 goto   @3                      ; 18000FE09 u=
222. 8
223. 0 ; 1WAY-BLOCK 223 INBOUNDS: 4 OUTBOUNDS: 224 [START=18000FE0E END=18000FF05] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
223. 0 ; USE: rsp.8,sp+1F0.4,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..1F0,sp+1F4..,SHADOW,ARGS,GLBHIGH)
223. 0 ; DEF: cf.1,of.1,rax.16,rcx.8,r8.8,r9.8,sp+BC.4,(zf.1,sf.1,pf.1,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..BC,sp+C0..,RET,SHADOW,ARGS,GLBHIGH)
223. 0 ; DNU: cf.1,of.1
223. 0 mov    call !__ROL4__<fast:_DWORD %var_6E8.4,char #0x1A.1>.4, eax.4 ; 18000FE15 u=sp+1F0.4   d=eax.4
223. 1 cfshl  %var_6E8.4, #0x1A.1, cf.1 ; 18000FE15 u=sp+1F0.4   d=cf.1
223. 2 und    of.1                    ; 18000FE15 u=           d=of.1
223. 3 xdu    eax.4, rax.8            ; 18000FE15 u=eax.4      d=rax^4.4
223. 4 mov    eax.4, %var_81C.4       ; 18000FE77 u=eax.4      d=sp+BC.4
223. 5 add    rsp.8, #0xBC.8, r8.8    ; 18000FEE8 u=rsp.8      d=r8.8
223. 6 mov    #0x40.8, rcx.8          ; 18000FEF0 u=           d=rcx.8
223. 7 mov    #0x5B.8, rdx.8          ; 18000FEF5 u=           d=rdx.8
223. 8 mov    #0x2F.8, r9.8           ; 18000FEFA u=           d=r9.8
223. 9 call   $sub_1800E4370          ; 18000FF00 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
223. 9
224. 0 ; 1WAY-BLOCK 224 INBOUNDS: 223 OUTBOUNDS: 3 [START=18000FF05 END=18000FF65] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
224. 0 ; DEF: sp+30.4
224. 0 mov    #0xC4.4, %var_8A8.4     ; 18000FF58 u=           d=sp+30.4
224. 1 goto   @3                      ; 18000FF60 u=
224. 1
225. 0 ; 1WAY-BLOCK 225 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000FF65 END=18000FF90] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
225. 0 ; USE: ds.2,sp+3C.1,(GLBLOW,sp+0..3C,sp+3D..,SHADOW,ARGS,GLBHIGH)
225. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+7D0.8
225. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
225. 0 mov    &($p_InLoadOrderModuleList_7).8, rcx.8 ; 18000FF6D u=           d=rcx.8
225. 1 xdu    [ds.2:(xdu.8((xdu.4(%var_89C.1) >>l #4.1))+&($p_InLoadOrderModuleList_7).8)].1, eax.4 ; 18000FF74 u=ds.2,sp+3C.1,(GLBLOW,sp+0..3C,sp+3D..,SHADOW,ARGS,GLBHIGH) d=eax.4
225. 2 cfshl  eax.4, #4.1, cf.1       ; 18000FF78 u=eax.4      d=cf.1
225. 3 mul    #0x10.4, eax.4, eax.4   ; 18000FF78 u=eax.4      d=eax.4
225. 4 und    of.1                    ; 18000FF78 u=           d=of.1
225. 5 setz   eax.4, #0.4, zf.1       ; 18000FF78 u=eax.4      d=zf.1
225. 6 setp   eax.4, #0.4, pf.1       ; 18000FF78 u=eax.4      d=pf.1
225. 7 sets   eax.4, sf.1             ; 18000FF78 u=eax.4      d=sf.1
225. 8 xdu    eax.4, rax.8            ; 18000FF78 u=eax.4      d=rax^4.4
225. 9 xdu    eax.4, %var_110@8.8     ; 18000FF7B u=eax.4      d=sp+7D0.8
225.10 mov    #0xCA.4, %var_8A8.4     ; 18000FF83 u=           d=sp+30.4
225.11 goto   @3                      ; 18000FF8B u=
225.11
226. 0 ; 1WAY-BLOCK 226 INBOUNDS: 4 OUTBOUNDS: 3 [START=18000FF90 END=180010023] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
226. 0 ; USE: sp+6F.1,sp+6C0..6D0
226. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+6D0..6E0
226. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
226. 0 or     %var_210.8, %var_218.8, %var_208.8 ; 18000FFA0 u=sp+6C0..6D0 d=sp+6D0.8
226. 1 xdu    (%var_870@7.1 & #0xF.1), rax.8 ; 180010001 u=sp+6F.1    d=rax.8
226. 2 cfadd  rax.8, &($p_InLoadOrderModuleList_5).8, cf.1 ; 18001000B u=rax.8      d=cf.1
226. 3 ofadd  rax.8, &($p_InLoadOrderModuleList_5).8, of.1 ; 18001000B u=rax.8      d=of.1
226. 4 setz   (rax.8+&($p_InLoadOrderModuleList_5).8), #0.8, zf.1 ; 18001000B u=rax.8      d=zf.1
226. 5 setp   (rax.8+&($p_InLoadOrderModuleList_5).8), #0.8, pf.1 ; 18001000B u=rax.8      d=pf.1
226. 6 sets   (rax.8+&($p_InLoadOrderModuleList_5).8), sf.1 ; 18001000B u=rax.8      d=sf.1
226. 7 add    rax.8, &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18001000B u=rax.8      d=rcx.8
226. 8 add    rax.8, &($p_InLoadOrderModuleList_5).8, %var_200.8 ; 18001000E u=rax.8      d=sp+6D8.8
226. 9 mov    #0xAF.4, %var_8A8.4     ; 180010016 u=           d=sp+30.4
226.10 goto   @3                      ; 18001001E u=
226.10
227. 0 ; 1WAY-BLOCK 227 INBOUNDS: 4 OUTBOUNDS: 3 [START=180010023 END=1800100B3] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
227. 0 ; USE: sp+588.8,180281BE0.8
227. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+2C8.8,sp+590.8
227. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
227. 0 mov    call !__ROL8__<fast:_QWORD %var_350.8,char #0xC.1>.8, rax.8 ; 18001002B u=sp+588.8   d=rax.8
227. 1 mov    $qword_180281BE0.8, rcx.8 ; 18001002F u=180281BE0.8 d=rcx.8
227. 2 mov    $qword_180281BE0.8, %var_610.8 ; 180010036 u=180281BE0.8 d=sp+2C8.8
227. 3 xor    $qword_180281BE0.8, rax.8, rax.8 ; 180010092 u=rax.8,180281BE0.8 d=rax.8
227. 4 setz   rax.8, #0.8, zf.1       ; 180010092 u=rax.8      d=zf.1
227. 5 setp   rax.8, #0.8, pf.1       ; 180010092 u=rax.8      d=pf.1
227. 6 sets   rax.8, sf.1             ; 180010092 u=rax.8      d=sf.1
227. 7 cfshl  rax.8, #0x21.1, tt.1    ; 18001009A u=rax.8      d=tt.1
227. 8 mov    call !__ROL8__<fast:_QWORD rax.8,char #0x21.1>.8, rax.8 ; 18001009A u=rax.8      d=rax.8
227. 9 mov    tt.1, cf.1              ; 18001009A u=tt.1       d=cf.1
227.10 und    of.1                    ; 18001009A u=           d=of.1
227.11 mov    rax.8, %var_348.8       ; 18001009E u=rax.8      d=sp+590.8
227.12 mov    #0x6A.4, %var_8A8.4     ; 1800100A6 u=           d=sp+30.4
227.13 goto   @3                      ; 1800100AE u=
227.13
228. 0 ; 1WAY-BLOCK 228 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800100B3 END=180010149] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
228. 0 ; USE: sp+59.1,sp+88.8,sp+1D4.4
228. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+1D8.4,sp+670.8
228. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
228. 0 or     %var_704.4, (#0x10.4*xdu.4(%var_87F.1)), %var_700.4 ; 1800100C2 u=sp+59.1,sp+1D4.4 d=sp+1D8.4
228. 1 shr    %var_850.8, #0x1C.1, rax.8 ; 180010126 u=sp+88.8    d=rax.8
228. 2 cfadd  (%var_850.8 >>l #0x1C.1), &($p_InLoadOrderModuleList_2).8, cf.1 ; 180010131 u=sp+88.8    d=cf.1
228. 3 ofadd  (%var_850.8 >>l #0x1C.1), &($p_InLoadOrderModuleList_2).8, of.1 ; 180010131 u=sp+88.8    d=of.1
228. 4 setz   ((%var_850.8 >>l #0x1C.1)+&($p_InLoadOrderModuleList_2).8), #0.8, zf.1 ; 180010131 u=sp+88.8    d=zf.1
228. 5 setp   ((%var_850.8 >>l #0x1C.1)+&($p_InLoadOrderModuleList_2).8), #0.8, pf.1 ; 180010131 u=sp+88.8    d=pf.1
228. 6 sets   ((%var_850.8 >>l #0x1C.1)+&($p_InLoadOrderModuleList_2).8), sf.1 ; 180010131 u=sp+88.8    d=sf.1
228. 7 add    (%var_850.8 >>l #0x1C.1), &($p_InLoadOrderModuleList_2).8, rcx.8 ; 180010131 u=sp+88.8    d=rcx.8
228. 8 add    (%var_850.8 >>l #0x1C.1), &($p_InLoadOrderModuleList_2).8, %var_268.8 ; 180010134 u=sp+88.8    d=sp+670.8
228. 9 mov    #0xA1.4, %var_8A8.4     ; 18001013C u=           d=sp+30.4
228.10 goto   @3                      ; 180010144 u=
228.10
229. 0 ; 1WAY-BLOCK 229 INBOUNDS: 4 OUTBOUNDS: 3 [START=180010149 END=180010189] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
229. 0 ; USE: ds.2,sp+68.1,sp+6B0..6C0,(GLBLOW,sp+0..68,sp+69..6B0,sp+6C0..,SHADOW,ARGS,GLBHIGH)
229. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+6C0..6D0
229. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
229. 0 or     %var_220.8, %var_228.8, %var_218.8 ; 180010159 u=sp+6B0..6C0 d=sp+6C0.8
229. 1 mov    #0.1, cf.1              ; 180010166 u=           d=cf.1
229. 2 mov    #0.1, of.1              ; 180010166 u=           d=of.1
229. 3 setz   xdu.4((%var_870.1 & #0xF.1)), #0.4, zf.1 ; 180010166 u=sp+68.1    d=zf.1
229. 4 setp   xdu.4((%var_870.1 & #0xF.1)), #0.4, pf.1 ; 180010166 u=sp+68.1    d=pf.1
229. 5 mov    #0.1, sf.1              ; 180010166 u=           d=sf.1
229. 6 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 180010169 u=           d=rcx.8
229. 7 xdu    [ds.2:(xdu.8((%var_870.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1, rax.8 ; 180010170 u=ds.2,sp+68.1,(GLBLOW,sp+0..68,sp+69..,SHADOW,ARGS,GLBHIGH) d=rax.8
229. 8 xdu    [ds.2:(xdu.8((%var_870.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1, %var_210.8 ; 180010174 u=ds.2,sp+68.1,(GLBLOW,sp+0..68,sp+69..,SHADOW,ARGS,GLBHIGH) d=sp+6C8.8
229. 9 mov    #0xAE.4, %var_8A8.4     ; 18001017C u=           d=sp+30.4
229.10 goto   @3                      ; 180010184 u=
229.10
230. 0 ; 1WAY-BLOCK 230 INBOUNDS: 4 OUTBOUNDS: 3 [START=180010189 END=1800101D3] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
230. 0 ; USE: ds.2,sp+80.8,sp+194.4,(GLBLOW,sp+0..80,sp+88..194,sp+198..,SHADOW,ARGS,GLBHIGH)
230. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+198.4,sp+648.8
230. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
230. 0 shr    %var_858.8, #8.1, %var_290.8 ; 180010195 u=sp+80.8    d=sp+648.8
230. 1 mov    &($p_InLoadOrderModuleList_6).8, rcx.8 ; 1800101AA u=           d=rcx.8
230. 2 mov    #0.1, cf.1              ; 1800101B8 u=           d=cf.1
230. 3 mov    #0.1, of.1              ; 1800101B8 u=           d=of.1
230. 4 setz   (%var_744.4 | (#0x1000.4*xdu.4([ds.2:(xdu.8((%var_858.2 >>l #0xC.1))+&($p_InLoadOrderModuleList_6).8)].1))), #0.4, zf.1 ; 1800101B8 u=ds.2,sp+80.2,sp+194.4,(GLBLOW,sp+0..80,sp+82..194,sp+198..,SHADOW,ARGS,GLBHIGH) d=zf.1
230. 5 setp   (%var_744.4 | (#0x1000.4*xdu.4([ds.2:(xdu.8((%var_858.2 >>l #0xC.1))+&($p_InLoadOrderModuleList_6).8)].1))), #0.4, pf.1 ; 1800101B8 u=ds.2,sp+80.2,sp+194.4,(GLBLOW,sp+0..80,sp+82..194,sp+198..,SHADOW,ARGS,GLBHIGH) d=pf.1
230. 6 sets   (%var_744.4 | (#0x1000.4*xdu.4([ds.2:(xdu.8((%var_858.2 >>l #0xC.1))+&($p_InLoadOrderModuleList_6).8)].1))), sf.1 ; 1800101B8 u=ds.2,sp+80.2,sp+194.4,(GLBLOW,sp+0..80,sp+82..194,sp+198..,SHADOW,ARGS,GLBHIGH) d=sf.1
230. 7 xdu    (%var_744.4 | (#0x1000.4*xdu.4([ds.2:(xdu.8((%var_858.2 >>l #0xC.1))+&($p_InLoadOrderModuleList_6).8)].1))), rax.8 ; 1800101B8 u=ds.2,sp+80.2,sp+194.4,(GLBLOW,sp+0..80,sp+82..194,sp+198..,SHADOW,ARGS,GLBHIGH) d=rax.8
230. 8 or     %var_744.4, (#0x1000.4*xdu.4([ds.2:(xdu.8((%var_858.2 >>l #0xC.1))+&($p_InLoadOrderModuleList_6).8)].1)), %var_740.4 ; 1800101BF u=ds.2,sp+80.2,sp+194.4,(GLBLOW,sp+0..80,sp+82..194,sp+198..,SHADOW,ARGS,GLBHIGH) d=sp+198.4
230. 9 mov    #0x90.4, %var_8A8.4     ; 1800101C6 u=           d=sp+30.4
230.10 goto   @3                      ; 1800101CE u=
230.10
231. 0 ; 1WAY-BLOCK 231 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800101D3 END=1800102BD] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
231. 0 ; USE: sp+BC.4,sp+FC.4
231. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+CC.4
231. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
231. 0 xor    (%var_7DC.4 ^ %var_81C.4), #0xD.4, eax.4 ; 180010231 u=sp+BC.4,sp+FC.4 d=eax.4
231. 1 setz   ((%var_7DC.4 ^ %var_81C.4) ^ #0xD.4), #0.4, zf.1 ; 180010231 u=sp+BC.4,sp+FC.4 d=zf.1
231. 2 setp   ((%var_7DC.4 ^ %var_81C.4) ^ #0xD.4), #0.4, pf.1 ; 180010231 u=sp+BC.4,sp+FC.4 d=pf.1
231. 3 sets   (%var_7DC.4 ^ %var_81C.4), sf.1 ; 180010231 u=sp+BC.4,sp+FC.4 d=sf.1
231. 4 cfshl  eax.4, #0xB.1, tt.1     ; 180010234 u=eax.4      d=tt.1
231. 5 mov    call !__ROL4__<fast:_DWORD eax.4,char #0xB.1>.4, eax.4 ; 180010234 u=eax.4      d=eax.4
231. 6 mov    tt.1, cf.1              ; 180010234 u=tt.1       d=cf.1
231. 7 und    of.1                    ; 180010234 u=           d=of.1
231. 8 xdu    eax.4, rax.8            ; 180010234 u=eax.4      d=rax^4.4
231. 9 mov    eax.4, %var_80C.4       ; 180010237 u=eax.4      d=sp+CC.4
231.10 mov    #0xC5.4, %var_8A8.4     ; 1800102B0 u=           d=sp+30.4
231.11 goto   @3                      ; 1800102B8 u=
231.11
232. 0 ; 1WAY-BLOCK 232 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800102BD END=1800102F1] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
232. 0 ; USE: ds.2,sp+198.4,sp+648.1,(GLBLOW,sp+0..198,sp+19C..648,sp+649..,SHADOW,ARGS,GLBHIGH)
232. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+19C.4
232. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
232. 0 mov    &($p_InLoadOrderModuleList_6).8, rcx.8 ; 1800102C8 u=           d=rcx.8
232. 1 mov    #0.1, cf.1              ; 1800102D6 u=           d=cf.1
232. 2 mov    #0.1, of.1              ; 1800102D6 u=           d=of.1
232. 3 setz   (%var_740.4 | (#0x100.4*xdu.4([ds.2:(xdu.8((%var_290.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1))), #0.4, zf.1 ; 1800102D6 u=ds.2,sp+198.4,sp+648.1,(GLBLOW,sp+0..198,sp+19C..648,sp+649..,SHADOW,ARGS,GLBHIGH) d=zf.1
232. 4 setp   (%var_740.4 | (#0x100.4*xdu.4([ds.2:(xdu.8((%var_290.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1))), #0.4, pf.1 ; 1800102D6 u=ds.2,sp+198.4,sp+648.1,(GLBLOW,sp+0..198,sp+19C..648,sp+649..,SHADOW,ARGS,GLBHIGH) d=pf.1
232. 5 sets   (%var_740.4 | (#0x100.4*xdu.4([ds.2:(xdu.8((%var_290.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1))), sf.1 ; 1800102D6 u=ds.2,sp+198.4,sp+648.1,(GLBLOW,sp+0..198,sp+19C..648,sp+649..,SHADOW,ARGS,GLBHIGH) d=sf.1
232. 6 xdu    (%var_740.4 | (#0x100.4*xdu.4([ds.2:(xdu.8((%var_290.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1))), rax.8 ; 1800102D6 u=ds.2,sp+198.4,sp+648.1,(GLBLOW,sp+0..198,sp+19C..648,sp+649..,SHADOW,ARGS,GLBHIGH) d=rax.8
232. 7 or     %var_740.4, (#0x100.4*xdu.4([ds.2:(xdu.8((%var_290.1 & #0xF.1))+&($p_InLoadOrderModuleList_6).8)].1)), %var_73C.4 ; 1800102DD u=ds.2,sp+198.4,sp+648.1,(GLBLOW,sp+0..198,sp+19C..648,sp+649..,SHADOW,ARGS,GLBHIGH) d=sp+19C.4
232. 8 mov    #0x91.4, %var_8A8.4     ; 1800102E4 u=           d=sp+30.4
232. 9 goto   @3                      ; 1800102EC u=
232. 9
233. 0 ; 1WAY-BLOCK 233 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800102F1 END=18001038D] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
233. 0 ; USE: sp+5A.1,sp+68.8
233. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+690..6A8
233. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
233. 0 mul    #0x10000000000000.8, xdu.8(%var_87E.1), %var_248.8 ; 1800102FA u=sp+5A.1    d=sp+690.8
233. 1 shr    %var_870.8, #0x18.1, %var_240.8 ; 180010369 u=sp+68.8    d=sp+698.8
233. 2 cfshr  %var_870.4, #0x1C.1, cf.1 ; 180010375 u=sp+68.4    d=cf.1
233. 3 und    of.1                    ; 180010375 u=           d=of.1
233. 4 setz   (%var_870.4 >>l #0x1C.1), #0.4, zf.1 ; 180010375 u=sp+68.4    d=zf.1
233. 5 setp   (%var_870.4 >>l #0x1C.1), #0.4, pf.1 ; 180010375 u=sp+68.4    d=pf.1
233. 6 mov    #0.1, sf.1              ; 180010375 u=           d=sf.1
233. 7 xdu    (%var_870.4 >>l #0x1C.1), rax.8 ; 180010375 u=sp+68.4    d=rax.8
233. 8 xdu    (%var_870.4 >>l #0x1C.1), %var_238.8 ; 180010378 u=sp+68.4    d=sp+6A0.8
233. 9 mov    #0xAA.4, %var_8A8.4     ; 180010380 u=           d=sp+30.4
233.10 goto   @3                      ; 180010388 u=
233.10
234. 0 ; 1WAY-BLOCK 234 INBOUNDS: 4 OUTBOUNDS: 3 [START=18001038D END=1800103D0] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
234. 0 ; USE: ds.2,sp+80.8,sp+19C.8,(GLBLOW,sp+0..80,sp+88..19C,sp+1A4..,SHADOW,ARGS,GLBHIGH)
234. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+1A4.8
234. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
234. 0 or     %var_73C.4, (#0x10.4*%var_738.4), %var_734.4 ; 18001039E u=sp+19C.8   d=sp+1A4.4
234. 1 cfshr  %var_858.8, #0x1C.1, cf.1 ; 1800103AD u=sp+80.8    d=cf.1
234. 2 und    of.1                    ; 1800103AD u=           d=of.1
234. 3 setz   (%var_858.8 >>l #0x1C.1), #0.8, zf.1 ; 1800103AD u=sp+80.8    d=zf.1
234. 4 setp   (%var_858.8 >>l #0x1C.1), #0.8, pf.1 ; 1800103AD u=sp+80.8    d=pf.1
234. 5 mov    #0.1, sf.1              ; 1800103AD u=           d=sf.1
234. 6 mov    &($p_InLoadOrderModuleList_6).8, rcx.8 ; 1800103B1 u=           d=rcx.8
234. 7 xdu    [ds.2:((%var_858.8 >>l #0x1C.1)+&($p_InLoadOrderModuleList_6).8)].1, rax.8 ; 1800103B8 u=ds.2,sp+80.8,(GLBLOW,sp+0..80,sp+88..,SHADOW,ARGS,GLBHIGH) d=rax.8
234. 8 xdu    [ds.2:((%var_858.8 >>l #0x1C.1)+&($p_InLoadOrderModuleList_6).8)].1, %var_730.4 ; 1800103BC u=ds.2,sp+80.8,(GLBLOW,sp+0..80,sp+88..,SHADOW,ARGS,GLBHIGH) d=sp+1A8.4
234. 9 mov    #0x93.4, %var_8A8.4     ; 1800103C3 u=           d=sp+30.4
234.10 goto   @3                      ; 1800103CB u=
234.10
235. 0 ; 1WAY-BLOCK 235 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800103D0 END=180010499] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
235. 0 ; USE: ds.2,sp+140.4,sp+338.1,(GLBLOW,sp+0..140,sp+144..338,sp+339..,SHADOW,ARGS,GLBHIGH)
235. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+144.4
235. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
235. 0 mov    &($p_InLoadOrderModuleList_1).8, rcx.8 ; 180010427 u=           d=rcx.8
235. 1 mov    #0.1, cf.1              ; 18001047E u=           d=cf.1
235. 2 mov    #0.1, of.1              ; 18001047E u=           d=of.1
235. 3 setz   (%var_798.4 | (#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_5A0.1 & #0xF.1))+&($p_InLoadOrderModuleList_1).8)].1))), #0.4, zf.1 ; 18001047E u=ds.2,sp+140.4,sp+338.1,(GLBLOW,sp+0..140,sp+144..338,sp+339..,SHADOW,ARGS,GLBHIGH) d=zf.1
235. 4 setp   (%var_798.4 | (#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_5A0.1 & #0xF.1))+&($p_InLoadOrderModuleList_1).8)].1))), #0.4, pf.1 ; 18001047E u=ds.2,sp+140.4,sp+338.1,(GLBLOW,sp+0..140,sp+144..338,sp+339..,SHADOW,ARGS,GLBHIGH) d=pf.1
235. 5 sets   (%var_798.4 | (#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_5A0.1 & #0xF.1))+&($p_InLoadOrderModuleList_1).8)].1))), sf.1 ; 18001047E u=ds.2,sp+140.4,sp+338.1,(GLBLOW,sp+0..140,sp+144..338,sp+339..,SHADOW,ARGS,GLBHIGH) d=sf.1
235. 6 xdu    (%var_798.4 | (#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_5A0.1 & #0xF.1))+&($p_InLoadOrderModuleList_1).8)].1))), rax.8 ; 18001047E u=ds.2,sp+140.4,sp+338.1,(GLBLOW,sp+0..140,sp+144..338,sp+339..,SHADOW,ARGS,GLBHIGH) d=rax.8
235. 7 or     %var_798.4, (#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_5A0.1 & #0xF.1))+&($p_InLoadOrderModuleList_1).8)].1)), %var_794.4 ; 180010485 u=ds.2,sp+140.4,sp+338.1,(GLBLOW,sp+0..140,sp+144..338,sp+339..,SHADOW,ARGS,GLBHIGH) d=sp+144.4
235. 8 mov    #0x2A.4, %var_8A8.4     ; 18001048C u=           d=sp+30.4
235. 9 goto   @3                      ; 180010494 u=
235. 9
236. 0 ; 1WAY-BLOCK 236 INBOUNDS: 4 OUTBOUNDS: 3 [START=180010499 END=1800104D6] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
236. 0 ; USE: ds.2,sp+68.1,sp+708..718,(GLBLOW,sp+0..68,sp+69..708,sp+718..,SHADOW,ARGS,GLBHIGH)
236. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+718..728
236. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
236. 0 or     %var_1D0.8, xdu.8((#0x1000000.4*xdu.4([ds.2:%var_1C8.8].1))), %var_1C0.8 ; 1800104AF u=ds.2,sp+708..718,(GLBLOW,sp+0..708,sp+718..,SHADOW,ARGS,GLBHIGH) d=sp+718.8
236. 1 mov    #0.1, cf.1              ; 1800104BE u=           d=cf.1
236. 2 mov    #0.1, of.1              ; 1800104BE u=           d=of.1
236. 3 setz   xdu.4((%var_870.1 >>l #4.1)), #0.4, zf.1 ; 1800104BE u=sp+68.1    d=zf.1
236. 4 setp   xdu.4((%var_870.1 >>l #4.1)), #0.4, pf.1 ; 1800104BE u=sp+68.1    d=pf.1
236. 5 mov    #0.1, sf.1              ; 1800104BE u=           d=sf.1
236. 6 xdu    (%var_870.1 >>l #4.1), rax.8 ; 1800104BE u=sp+68.1    d=rax.8
236. 7 xdu    (%var_870.1 >>l #4.1), %var_1B8.8 ; 1800104C1 u=sp+68.1    d=sp+720.8
236. 8 mov    #0xB4.4, %var_8A8.4     ; 1800104C9 u=           d=sp+30.4
236. 9 goto   @3                      ; 1800104D1 u=
236. 9
237. 0 ; 1WAY-BLOCK 237 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800104D6 END=1800105C2] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
237. 0 ; USE: sp+520.1,sp+530..540
237. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+540..550
237. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
237. 0 or     %var_3A8.8, (#0x100.8*%var_3A0.8), %var_398.8 ; 18001059A u=sp+530..540 d=sp+540.8
237. 1 mov    #0.1, cf.1              ; 1800105AA u=           d=cf.1
237. 2 mov    #0.1, of.1              ; 1800105AA u=           d=of.1
237. 3 setz   xdu.4((%var_3B8.1 & #0xF.1)), #0.4, zf.1 ; 1800105AA u=sp+520.1   d=zf.1
237. 4 setp   xdu.4((%var_3B8.1 & #0xF.1)), #0.4, pf.1 ; 1800105AA u=sp+520.1   d=pf.1
237. 5 mov    #0.1, sf.1              ; 1800105AA u=           d=sf.1
237. 6 xdu    (%var_3B8.1 & #0xF.1), rax.8 ; 1800105AA u=sp+520.1   d=rax.8
237. 7 xdu    (%var_3B8.1 & #0xF.1), %var_390.8 ; 1800105AD u=sp+520.1   d=sp+548.8
237. 8 mov    #0x5E.4, %var_8A8.4     ; 1800105B5 u=           d=sp+30.4
237. 9 goto   @3                      ; 1800105BD u=
237. 9
238. 0 ; 1WAY-BLOCK 238 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800105C2 END=180010669] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
238. 0 ; USE: ds.2,sp+1B4.1,sp+650.8,(GLBLOW,sp+0..1B4,sp+1B5..650,sp+658..,SHADOW,ARGS,GLBHIGH)
238. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+3B.1,sp+1B8.4
238. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
238. 0 mov    &($p_InLoadOrderModuleList_2).8, rcx.8 ; 1800105CA u=           d=rcx.8
238. 1 xdu    [ds.2:(%var_288.8+&($p_InLoadOrderModuleList_2).8)].1, eax.4 ; 1800105D1 u=ds.2,sp+650.8,(GLBLOW,sp+0..650,sp+658..,SHADOW,ARGS,GLBHIGH) d=eax.4
238. 2 cfshl  eax.4, #0x18.1, cf.1    ; 180010646 u=eax.4      d=cf.1
238. 3 mul    #0x1000000.4, eax.4, eax.4 ; 180010646 u=eax.4      d=eax.4
238. 4 und    of.1                    ; 180010646 u=           d=of.1
238. 5 setz   eax.4, #0.4, zf.1       ; 180010646 u=eax.4      d=zf.1
238. 6 setp   eax.4, #0.4, pf.1       ; 180010646 u=eax.4      d=pf.1
238. 7 sets   eax.4, sf.1             ; 180010646 u=eax.4      d=sf.1
238. 8 mov    eax.4, %var_720.4       ; 180010649 u=eax.4      d=sp+1B8.4
238. 9 xdu    %var_724.1, rax.8       ; 180010650 u=sp+1B4.1   d=rax.8
238.10 mov    %var_724.1, %var_89D.1  ; 180010658 u=sp+1B4.1   d=sp+3B.1
238.11 mov    #0x99.4, %var_8A8.4     ; 18001065C u=           d=sp+30.4
238.12 goto   @3                      ; 180010664 u=
238.12
239. 0 ; 1WAY-BLOCK 239 INBOUNDS: 4 OUTBOUNDS: 240 [START=180010669 END=180010686] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
239. 0 ; USE: rsp.8,(rax.8,rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH)
239. 0 ; DEF: rdx.8,rcx.8,r8.8,r9.8,(cf.1,zf.1,sf.1,of.1,pf.1,rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm4.16,xmm5.16,ALLMEM)
239. 0 add    rsp.8, #0x9C.8, r8.8    ; 180010669 u=rsp.8      d=r8.8
239. 1 mov    #0x5A.8, rcx.8          ; 180010671 u=           d=rcx.8
239. 2 mov    #0xA.8, rdx.8           ; 180010676 u=           d=rdx.8
239. 3 mov    #0xD.8, r9.8            ; 18001067B u=           d=r9.8
239. 4 call   $sub_18011C8C0          ; 180010681 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm4.16,xmm5.16,ALLMEM)
239. 4
240. 0 ; 1WAY-BLOCK 240 INBOUNDS: 239 OUTBOUNDS: 3 [START=180010686 END=180010725] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
240. 0 ; USE: sp+9C.4,180281BFA.4
240. 0 ; DEF: rax.8,sp+30.4,sp+154.8
240. 0 ; DNU: rax.8
240. 0 mov    %var_83C.4, %var_784.4  ; 18001068D u=sp+9C.4    d=sp+154.4
240. 1 xdu    $qword_180281BFA.4, rax.8 ; 180010694 u=180281BFA.4 d=rax.8
240. 2 mov    $qword_180281BFA.4, %var_780.4 ; 18001069A u=180281BFA.4 d=sp+158.4
240. 3 mov    #0x2F.4, %var_8A8.4     ; 180010718 u=           d=sp+30.4
240. 4 goto   @3                      ; 180010720 u=
240. 4
241. 0 ; 1WAY-BLOCK 241 INBOUNDS: 4 OUTBOUNDS: 3 [START=180010725 END=1800107A3] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
241. 0 ; USE: sp+1A4.8
241. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+B0.4
241. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
241. 0 mov    call !__ROL4__<fast:_DWORD (%var_734.4 | (#0x10000000.4*%var_730.4)),char #6.1>.4, eax.4 ; 180010782 u=sp+1A4.8   d=eax.4
241. 1 xor    eax.4, #0x238F0F50.4, eax.4 ; 180010785 u=eax.4      d=eax.4
241. 2 cfadd  eax.4, #0x29D0E15.4, cf.1 ; 18001078A u=eax.4      d=cf.1
241. 3 ofadd  #0x29D0E15.4, eax.4, of.1 ; 18001078A u=eax.4      d=of.1
241. 4 setz   (eax.4+#0x29D0E15.4), #0.4, zf.1 ; 18001078A u=eax.4      d=zf.1
241. 5 setp   (eax.4+#0x29D0E15.4), #0.4, pf.1 ; 18001078A u=eax.4      d=pf.1
241. 6 sets   (eax.4+#0x29D0E15.4), sf.1 ; 18001078A u=eax.4      d=sf.1
241. 7 xdu    (eax.4+#0x29D0E15.4), rax.8 ; 18001078A u=eax.4      d=rax.8
241. 8 mov    eax.4, %var_828.4       ; 18001078F u=eax.4      d=sp+B0.4
241. 9 mov    #0x94.4, %var_8A8.4     ; 180010796 u=           d=sp+30.4
241.10 goto   @3                      ; 18001079E u=
241.10
242. 0 ; 1WAY-BLOCK 242 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800107A3 END=1800107DE] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
242. 0 ; USE: ds.2,sp+150.4,sp+360.8,(GLBLOW,sp+0..150,sp+154..360,sp+368..,SHADOW,ARGS,GLBHIGH)
242. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+9C.4
242. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
242. 0 mov    &($p_InLoadOrderModuleList_1).8, rcx.8 ; 1800107AB u=           d=rcx.8
242. 1 mov    #0.1, cf.1              ; 1800107C5 u=           d=cf.1
242. 2 mov    #0.1, of.1              ; 1800107C5 u=           d=of.1
242. 3 setz   (((%var_788.4 | (#0x10000.4*xdu.4([ds.2:(%var_578.8+&($p_InLoadOrderModuleList_1).8)].1)))+#0x71DCDC6A.4) ^ #0xA70B480C.4), #0.4, zf.1 ; 1800107C5 u=ds.2,sp+150.4,sp+360.8,(GLBLOW,sp+0..150,sp+154..360,sp+368..,SHADOW,ARGS,GLBHIGH) d=zf.1
242. 4 setp   (((%var_788.4 | (#0x10000.4*xdu.4([ds.2:(%var_578.8+&($p_InLoadOrderModuleList_1).8)].1)))+#0x71DCDC6A.4) ^ #0xA70B480C.4), #0.4, pf.1 ; 1800107C5 u=ds.2,sp+150.4,sp+360.8,(GLBLOW,sp+0..150,sp+154..360,sp+368..,SHADOW,ARGS,GLBHIGH) d=pf.1
242. 5 sets   bnot(((%var_788.4 | (#0x10000.4*xdu.4([ds.2:(%var_578.8+&($p_InLoadOrderModuleList_1).8)].1)))+#0x71DCDC6A.4)), sf.1 ; 1800107C5 u=ds.2,sp+150.4,sp+360.8,(GLBLOW,sp+0..150,sp+154..360,sp+368..,SHADOW,ARGS,GLBHIGH) d=sf.1
242. 6 xdu    (((%var_788.4 | (#0x10000.4*xdu.4([ds.2:(%var_578.8+&($p_InLoadOrderModuleList_1).8)].1)))+#0x71DCDC6A.4) ^ #0xA70B480C.4), rax.8 ; 1800107C5 u=ds.2,sp+150.4,sp+360.8,(GLBLOW,sp+0..150,sp+154..360,sp+368..,SHADOW,ARGS,GLBHIGH) d=rax.8
242. 7 xor    ((%var_788.4 | (#0x10000.4*xdu.4([ds.2:(%var_578.8+&($p_InLoadOrderModuleList_1).8)].1)))+#0x71DCDC6A.4), #0xA70B480C.4, %var_83C.4 ; 1800107CA u=ds.2,sp+150.4,sp+360.8,(GLBLOW,sp+0..150,sp+154..360,sp+368..,SHADOW,ARGS,GLBHIGH) d=sp+9C.4
242. 8 mov    #0x2E.4, %var_8A8.4     ; 1800107D1 u=           d=sp+30.4
242. 9 goto   @3                      ; 1800107D9 u=
242. 9
243. 0 ; 1WAY-BLOCK 243 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800107DE END=180010855] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
243. 0 ; USE: sp+5A8.8
243. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+5B0.8
243. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
243. 0 mov    call !__ROL8__<fast:_QWORD (%var_330.8-#0x39B39BF2411BD27C.8),char #0x22.1>.8, rax.8 ; 1800107F0 u=sp+5A8.8   d=rax.8
243. 1 mov    #-0x5B27C99487A6D83D.8, rcx.8 ; 1800107F4 u=           d=rcx.8
243. 2 xor    rax.8, #-0x5B27C99487A6D83D.8, rax.8 ; 1800107FE u=rax.8      d=rax.8
243. 3 mov    #0.1, cf.1              ; 1800107FE u=           d=cf.1
243. 4 mov    #0.1, of.1              ; 1800107FE u=           d=of.1
243. 5 setz   rax.8, #0.8, zf.1       ; 1800107FE u=rax.8      d=zf.1
243. 6 setp   rax.8, #0.8, pf.1       ; 1800107FE u=rax.8      d=pf.1
243. 7 sets   rax.8, sf.1             ; 1800107FE u=rax.8      d=sf.1
243. 8 mov    rax.8, %var_328.8       ; 180010801 u=rax.8      d=sp+5B0.8
243. 9 mov    #0x72.4, %var_8A8.4     ; 180010848 u=           d=sp+30.4
243.10 goto   @3                      ; 180010850 u=
243.10
244. 0 ; 1WAY-BLOCK 244 INBOUNDS: 4 OUTBOUNDS: 3 [START=180010855 END=18001089F] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
244. 0 ; USE: ds.2,sp+88.8,sp+1C8.4,(GLBLOW,sp+0..88,sp+90..1C8,sp+1CC..,SHADOW,ARGS,GLBHIGH)
244. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+1CC.4,sp+668.8
244. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
244. 0 shr    %var_850.8, #8.1, %var_270.8 ; 180010861 u=sp+88.8    d=sp+668.8
244. 1 mov    &($p_InLoadOrderModuleList_2).8, rcx.8 ; 180010876 u=           d=rcx.8
244. 2 mov    #0.1, cf.1              ; 180010884 u=           d=cf.1
244. 3 mov    #0.1, of.1              ; 180010884 u=           d=of.1
244. 4 setz   (%var_710.4 | (#0x1000.4*xdu.4([ds.2:(xdu.8((%var_850.2 >>l #0xC.1))+&($p_InLoadOrderModuleList_2).8)].1))), #0.4, zf.1 ; 180010884 u=ds.2,sp+88.2,sp+1C8.4,(GLBLOW,sp+0..88,sp+8A..1C8,sp+1CC..,SHADOW,ARGS,GLBHIGH) d=zf.1
244. 5 setp   (%var_710.4 | (#0x1000.4*xdu.4([ds.2:(xdu.8((%var_850.2 >>l #0xC.1))+&($p_InLoadOrderModuleList_2).8)].1))), #0.4, pf.1 ; 180010884 u=ds.2,sp+88.2,sp+1C8.4,(GLBLOW,sp+0..88,sp+8A..1C8,sp+1CC..,SHADOW,ARGS,GLBHIGH) d=pf.1
244. 6 sets   (%var_710.4 | (#0x1000.4*xdu.4([ds.2:(xdu.8((%var_850.2 >>l #0xC.1))+&($p_InLoadOrderModuleList_2).8)].1))), sf.1 ; 180010884 u=ds.2,sp+88.2,sp+1C8.4,(GLBLOW,sp+0..88,sp+8A..1C8,sp+1CC..,SHADOW,ARGS,GLBHIGH) d=sf.1
244. 7 xdu    (%var_710.4 | (#0x1000.4*xdu.4([ds.2:(xdu.8((%var_850.2 >>l #0xC.1))+&($p_InLoadOrderModuleList_2).8)].1))), rax.8 ; 180010884 u=ds.2,sp+88.2,sp+1C8.4,(GLBLOW,sp+0..88,sp+8A..1C8,sp+1CC..,SHADOW,ARGS,GLBHIGH) d=rax.8
244. 8 or     %var_710.4, (#0x1000.4*xdu.4([ds.2:(xdu.8((%var_850.2 >>l #0xC.1))+&($p_InLoadOrderModuleList_2).8)].1)), %var_70C.4 ; 18001088B u=ds.2,sp+88.2,sp+1C8.4,(GLBLOW,sp+0..88,sp+8A..1C8,sp+1CC..,SHADOW,ARGS,GLBHIGH) d=sp+1CC.4
244. 9 mov    #0x9E.4, %var_8A8.4     ; 180010892 u=           d=sp+30.4
244.10 goto   @3                      ; 18001089A u=
244.10
245. 0 ; 1WAY-BLOCK 245 INBOUNDS: 4 OUTBOUNDS: 3 [START=18001089F END=180010932] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
245. 0 ; USE: ds.2,sp+668.1,(GLBLOW,sp+0..668,sp+669..,SHADOW,ARGS,GLBHIGH)
245. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+1D0.4
245. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
245. 0 mov    &($p_InLoadOrderModuleList_2).8, rcx.8 ; 180010910 u=           d=rcx.8
245. 1 xdu    [ds.2:(xdu.8((%var_270.1 & #0xF.1))+&($p_InLoadOrderModuleList_2).8)].1, eax.4 ; 180010917 u=ds.2,sp+668.1,(GLBLOW,sp+0..668,sp+669..,SHADOW,ARGS,GLBHIGH) d=eax.4
245. 2 cfshl  eax.4, #8.1, cf.1       ; 18001091B u=eax.4      d=cf.1
245. 3 mul    #0x100.4, eax.4, eax.4  ; 18001091B u=eax.4      d=eax.4
245. 4 und    of.1                    ; 18001091B u=           d=of.1
245. 5 setz   eax.4, #0.4, zf.1       ; 18001091B u=eax.4      d=zf.1
245. 6 setp   eax.4, #0.4, pf.1       ; 18001091B u=eax.4      d=pf.1
245. 7 sets   eax.4, sf.1             ; 18001091B u=eax.4      d=sf.1
245. 8 xdu    eax.4, rax.8            ; 18001091B u=eax.4      d=rax^4.4
245. 9 mov    eax.4, %var_708.4       ; 18001091E u=eax.4      d=sp+1D0.4
245.10 mov    #0x9F.4, %var_8A8.4     ; 180010925 u=           d=sp+30.4
245.11 goto   @3                      ; 18001092D u=
245.11
246. 0 ; 1WAY-BLOCK 246 INBOUNDS: 4 OUTBOUNDS: 3 [START=180010932 END=180010951] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
246. 0 ; USE: ds.2,sp+590.8,(GLBLOW,sp+0..590,sp+598..,SHADOW,ARGS,GLBHIGH)
246. 0 ; DEF: rax.8,sp+30.4,sp+164.4
246. 0 ; DNU: rax.8
246. 0 xdu    [ds.2:(%var_348.8+#4.8)].4, rax.8 ; 18001093A u=ds.2,sp+590.8,(GLBLOW,sp+0..590,sp+598..,SHADOW,ARGS,GLBHIGH) d=rax.8
246. 1 ldx    ds.2, (%var_348.8+#4.8), %var_774.4 ; 18001093D u=ds.2,sp+590.8,(GLBLOW,sp+0..590,sp+598..,SHADOW,ARGS,GLBHIGH) d=sp+164.4
246. 2 mov    #0x6B.4, %var_8A8.4     ; 180010944 u=           d=sp+30.4
246. 3 goto   @3                      ; 18001094C u=
246. 3
247. 0 ; 1WAY-BLOCK 247 INBOUNDS: 4 OUTBOUNDS: 3 [START=180010951 END=1800109BE] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
247. 0 ; USE: ds.2,sp+42.1,(GLBLOW,sp+0..42,sp+43..,SHADOW,ARGS,GLBHIGH)
247. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+398.8
247. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4,rcx.8
247. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 180010959 u=           d=rcx.8
247. 1 xdu    [ds.2:(xdu.8((%var_898@2.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1, eax.4 ; 180010960 u=ds.2,sp+42.1,(GLBLOW,sp+0..42,sp+43..,SHADOW,ARGS,GLBHIGH) d=eax.4
247. 2 cfshl  eax.4, #0x10.1, cf.1    ; 1800109A6 u=eax.4      d=cf.1
247. 3 mul    #0x10000.4, eax.4, eax.4 ; 1800109A6 u=eax.4      d=eax.4
247. 4 und    of.1                    ; 1800109A6 u=           d=of.1
247. 5 setz   eax.4, #0.4, zf.1       ; 1800109A6 u=eax.4      d=zf.1
247. 6 setp   eax.4, #0.4, pf.1       ; 1800109A6 u=eax.4      d=pf.1
247. 7 sets   eax.4, sf.1             ; 1800109A6 u=eax.4      d=sf.1
247. 8 xdu    eax.4, rax.8            ; 1800109A6 u=eax.4      d=rax^4.4
247. 9 xdu    eax.4, %var_540.8       ; 1800109A9 u=eax.4      d=sp+398.8
247.10 mov    #0x35.4, %var_8A8.4     ; 1800109B1 u=           d=sp+30.4
247.11 goto   @3                      ; 1800109B9 u=
247.11
248. 0 ; 1WAY-BLOCK 248 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800109BE END=180010AA2] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
248. 0 ; USE: ds.2,sp+378.8,sp+388.8,(GLBLOW,sp+0..378,sp+380.8,sp+390..,SHADOW,ARGS,GLBHIGH)
248. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+390.8
248. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
248. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 180010A19 u=           d=rcx.8
248. 1 or     %var_560.8, (#0x10000000.8*xdu.8([ds.2:(%var_550.8+&($p_InLoadOrderModuleList_5).8)].1)), rax.8 ; 180010A28 u=ds.2,sp+378.8,sp+388.8,(GLBLOW,sp+0..378,sp+380.8,sp+390..,SHADOW,ARGS,GLBHIGH) d=rax.8
248. 2 mov    #0.1, cf.1              ; 180010A28 u=           d=cf.1
248. 3 mov    #0.1, of.1              ; 180010A28 u=           d=of.1
248. 4 setz   (%var_560.8 | (#0x10000000.8*xdu.8([ds.2:(%var_550.8+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, zf.1 ; 180010A28 u=ds.2,sp+378.8,sp+388.8,(GLBLOW,sp+0..378,sp+380.8,sp+390..,SHADOW,ARGS,GLBHIGH) d=zf.1
248. 5 setp   (%var_560.8 | (#0x10000000.8*xdu.8([ds.2:(%var_550.8+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, pf.1 ; 180010A28 u=ds.2,sp+378.8,sp+388.8,(GLBLOW,sp+0..378,sp+380.8,sp+390..,SHADOW,ARGS,GLBHIGH) d=pf.1
248. 6 sets   (%var_560.8 | (#0x10000000.8*xdu.8([ds.2:(%var_550.8+&($p_InLoadOrderModuleList_5).8)].1))), sf.1 ; 180010A28 u=ds.2,sp+378.8,sp+388.8,(GLBLOW,sp+0..378,sp+380.8,sp+390..,SHADOW,ARGS,GLBHIGH) d=sf.1
248. 7 or     %var_560.8, (#0x10000000.8*xdu.8([ds.2:(%var_550.8+&($p_InLoadOrderModuleList_5).8)].1)), %var_548.8 ; 180010A30 u=ds.2,sp+378.8,sp+388.8,(GLBLOW,sp+0..378,sp+380.8,sp+390..,SHADOW,ARGS,GLBHIGH) d=sp+390.8
248. 8 mov    #0x34.4, %var_8A8.4     ; 180010A95 u=           d=sp+30.4
248. 9 goto   @3                      ; 180010A9D u=
248. 9
249. 0 ; 1WAY-BLOCK 249 INBOUNDS: 4 OUTBOUNDS: 3 [START=180010AA2 END=180010B15] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
249. 0 ; USE: sp+578.8
249. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+580.8
249. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
249. 0 mov    call !__ROL8__<fast:_QWORD %var_360.8,char #0x1F.1>.8, rax.8 ; 180010AAA u=sp+578.8   d=rax.8
249. 1 setz   (rax.8 ^ #-0x199FCDDC515B2A89.8), #0.8, zf.1 ; 180010AF9 u=rax.8      d=zf.1
249. 2 setp   (rax.8 ^ #-0x199FCDDC515B2A89.8), #0.8, pf.1 ; 180010AF9 u=rax.8      d=pf.1
249. 3 sets   bnot(rax.8), sf.1       ; 180010AF9 u=rax.8      d=sf.1
249. 4 mov    call !__ROL8__<fast:_QWORD (rax.8 ^ #-0x199FCDDC515B2A89.8),char #0x34.1>.8, rcx.8 ; 180010AFC u=rax.8      d=rcx.8
249. 5 cfshl  (rax.8 ^ #-0x199FCDDC515B2A89.8), #0x34.1, cf.1 ; 180010AFC u=rax.8      d=cf.1
249. 6 und    of.1                    ; 180010AFC u=           d=of.1
249. 7 mov    rcx.8, %var_358.8       ; 180010B00 u=rcx.8      d=sp+580.8
249. 8 mov    #0x66.4, %var_8A8.4     ; 180010B08 u=           d=sp+30.4
249. 9 goto   @3                      ; 180010B10 u=
249. 9
250. 0 ; 1WAY-BLOCK 250 INBOUNDS: 4 OUTBOUNDS: 251 [START=180010B15 END=180010B33] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
250. 0 ; USE: rsp.8,(rax.8,rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH)
250. 0 ; DEF: rdx.8,rcx.8,r8.8,r9.8,(cf.1,zf.1,sf.1,of.1,pf.1,rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
250. 0 add    rsp.8, #0xB4.8, rcx.8   ; 180010B15 u=rsp.8      d=rcx.8
250. 1 mov    #0x3D.8, rdx.8          ; 180010B1D u=           d=rdx.8
250. 2 mov    #0x3B.8, r8.8           ; 180010B22 u=           d=r8.8
250. 3 mov    #0x3A.8, r9.8           ; 180010B28 u=           d=r9.8
250. 4 call   $sub_1801EEDD0          ; 180010B2E u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
250. 4
251. 0 ; 1WAY-BLOCK 251 INBOUNDS: 250 OUTBOUNDS: 3 [START=180010B33 END=180010C36] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
251. 0 ; USE: sp+B4.4
251. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+1B0.4
251. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
251. 0 mov    #0.1, cf.1              ; 180010C1D u=           d=cf.1
251. 1 mov    #0.1, of.1              ; 180010C1D u=           d=of.1
251. 2 setz   ((%var_824.4-#0x29D0E15.4) ^ #0x238F0F50.4), #0.4, zf.1 ; 180010C1D u=sp+B4.4    d=zf.1
251. 3 setp   ((%var_824.4-#0x29D0E15.4) ^ #0x238F0F50.4), #0.4, pf.1 ; 180010C1D u=sp+B4.4    d=pf.1
251. 4 sets   (%var_824.4-#0x29D0E15.4), sf.1 ; 180010C1D u=sp+B4.4    d=sf.1
251. 5 xdu    ((%var_824.4-#0x29D0E15.4) ^ #0x238F0F50.4), rax.8 ; 180010C1D u=sp+B4.4    d=rax.8
251. 6 xor    (%var_824.4-#0x29D0E15.4), #0x238F0F50.4, %var_728.4 ; 180010C22 u=sp+B4.4    d=sp+1B0.4
251. 7 mov    #0x97.4, %var_8A8.4     ; 180010C29 u=           d=sp+30.4
251. 8 goto   @3                      ; 180010C31 u=
251. 8
252. 0 ; 1WAY-BLOCK 252 INBOUNDS: 4 OUTBOUNDS: 253 [START=180010C36 END=180010C64] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
252. 0 ; USE: rsp.8,sp+368.8,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..368,sp+370..,SHADOW,ARGS,GLBHIGH)
252. 0 ; DEF: rax.16,rcx.8,r8.8,r9.8,sp+250.8,(cf.1,zf.1,sf.1,of.1,pf.1,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm4.16,xmm5.16,GLBLOW,sp+0..250,sp+258..,RET,SHADOW,ARGS,GLBHIGH)
252. 0 mov    %var_570.8, rax.8       ; 180010C36 u=sp+368.8   d=rax.8
252. 1 mov    %var_570.8, %var_688.8  ; 180010C3E u=sp+368.8   d=sp+250.8
252. 2 add    rsp.8, #0x250.8, rdx.8  ; 180010C46 u=rsp.8      d=rdx.8
252. 3 mov    #0x4B.8, rcx.8          ; 180010C4E u=           d=rcx.8
252. 4 mov    #0x48.8, r8.8           ; 180010C53 u=           d=r8.8
252. 5 mov    #0x55.8, r9.8           ; 180010C59 u=           d=r9.8
252. 6 call   $sub_1800A91F0          ; 180010C5F u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm4.16,xmm5.16,ALLMEM)
252. 6
253. 0 ; 1WAY-BLOCK 253 INBOUNDS: 252 OUTBOUNDS: 3 [START=180010C64 END=180010C85] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
253. 0 ; USE: rdi.8,sp+250.8
253. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+40.8
253. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
253. 0 mov    call !__ROL8__<fast:_QWORD %var_688.8,char #0x35.1>.8, rax.8 ; 180010C6C u=sp+250.8   d=rax.8
253. 1 cfadd  rdi.8, rax.8, cf.1      ; 180010C70 u=rax.8,rdi.8 d=cf.1
253. 2 ofadd  rdi.8, rax.8, of.1      ; 180010C70 u=rax.8,rdi.8 d=of.1
253. 3 setz   (rdi.8+rax.8), #0.8, zf.1 ; 180010C70 u=rax.8,rdi.8 d=zf.1
253. 4 setp   (rdi.8+rax.8), #0.8, pf.1 ; 180010C70 u=rax.8,rdi.8 d=pf.1
253. 5 sets   (rdi.8+rax.8), sf.1     ; 180010C70 u=rax.8,rdi.8 d=sf.1
253. 6 add    rdi.8, rax.8, rax.8     ; 180010C70 u=rax.8,rdi.8 d=rax.8
253. 7 mov    rax.8, %var_898.8       ; 180010C73 u=rax.8      d=sp+40.8
253. 8 mov    #0x31.4, %var_8A8.4     ; 180010C78 u=           d=sp+30.4
253. 9 goto   @3                      ; 180010C80 u=
253. 9
254. 0 ; 1WAY-BLOCK 254 INBOUNDS: 4 OUTBOUNDS: 255 [START=180010C85 END=180010D09] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
254. 0 ; USE: rsp.8,sp+460.8,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..460,sp+468..,SHADOW,ARGS,GLBHIGH)
254. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,sp+258.8,(r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm4.16,xmm5.16,GLBLOW,sp+0..258,sp+260..,RET,SHADOW,ARGS,GLBHIGH)
254. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
254. 0 xor    %var_478.8, #0x72.8, rax.8 ; 180010CDF u=sp+460.8   d=rax.8
254. 1 mov    #0.1, cf.1              ; 180010CDF u=           d=cf.1
254. 2 mov    #0.1, of.1              ; 180010CDF u=           d=of.1
254. 3 setz   (%var_478.8 ^ #0x72.8), #0.8, zf.1 ; 180010CDF u=sp+460.8   d=zf.1
254. 4 setp   (%var_478.8 ^ #0x72.8), #0.8, pf.1 ; 180010CDF u=sp+460.8   d=pf.1
254. 5 sets   %var_478.8, sf.1        ; 180010CDF u=sp+460.8   d=sf.1
254. 6 xor    %var_478.8, #0x72.8, %var_680.8 ; 180010CE3 u=sp+460.8   d=sp+258.8
254. 7 add    rsp.8, #0x258.8, rdx.8  ; 180010CEB u=rsp.8      d=rdx.8
254. 8 mov    #0xF.8, rcx.8           ; 180010CF3 u=           d=rcx.8
254. 9 mov    #0x11.8, r8.8           ; 180010CF8 u=           d=r8.8
254.10 mov    #6.8, r9.8              ; 180010CFE u=           d=r9.8
254.11 call   $sub_1800A91F0          ; 180010D04 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm4.16,xmm5.16,ALLMEM)
254.11
255. 0 ; 1WAY-BLOCK 255 INBOUNDS: 254 OUTBOUNDS: 3 [START=180010D09 END=180010D16] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
255. 0 ; DEF: sp+30.4
255. 0 mov    #0x4C.4, %var_8A8.4     ; 180010D09 u=           d=sp+30.4
255. 1 goto   @3                      ; 180010D11 u=
255. 1
256. 0 ; 1WAY-BLOCK 256 INBOUNDS: 4 OUTBOUNDS: 3 [START=180010D16 END=180010DF1] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
256. 0 ; USE: ds.2,sp+4C0.8,sp+4D0.8,(GLBLOW,sp+0..4C0,sp+4C8.8,sp+4D8..,SHADOW,ARGS,GLBHIGH)
256. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+4D8.8
256. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
256. 0 or     %var_418.8, xdu.8((#0x1000.4*xdu.4([ds.2:%var_408.8].1))), rax.8 ; 180010D24 u=ds.2,sp+4C0.8,sp+4D0.8,(GLBLOW,sp+0..4C0,sp+4C8.8,sp+4D8..,SHADOW,ARGS,GLBHIGH) d=rax.8
256. 1 mov    #0.1, cf.1              ; 180010D24 u=           d=cf.1
256. 2 mov    #0.1, of.1              ; 180010D24 u=           d=of.1
256. 3 setz   (%var_418.8 | xdu.8((#0x1000.4*xdu.4([ds.2:%var_408.8].1)))), #0.8, zf.1 ; 180010D24 u=ds.2,sp+4C0.8,sp+4D0.8,(GLBLOW,sp+0..4C0,sp+4C8.8,sp+4D8..,SHADOW,ARGS,GLBHIGH) d=zf.1
256. 4 setp   (%var_418.8 | xdu.8((#0x1000.4*xdu.4([ds.2:%var_408.8].1)))), #0.8, pf.1 ; 180010D24 u=ds.2,sp+4C0.8,sp+4D0.8,(GLBLOW,sp+0..4C0,sp+4C8.8,sp+4D8..,SHADOW,ARGS,GLBHIGH) d=pf.1
256. 5 sets   (%var_418.8 | xdu.8((#0x1000.4*xdu.4([ds.2:%var_408.8].1)))), sf.1 ; 180010D24 u=ds.2,sp+4C0.8,sp+4D0.8,(GLBLOW,sp+0..4C0,sp+4C8.8,sp+4D8..,SHADOW,ARGS,GLBHIGH) d=sf.1
256. 6 or     %var_418.8, xdu.8((#0x1000.4*xdu.4([ds.2:%var_408.8].1))), %var_400.8 ; 180010D2C u=ds.2,sp+4C0.8,sp+4D0.8,(GLBLOW,sp+0..4C0,sp+4C8.8,sp+4D8..,SHADOW,ARGS,GLBHIGH) d=sp+4D8.8
256. 7 mov    #0x56.4, %var_8A8.4     ; 180010DE4 u=           d=sp+30.4
256. 8 goto   @3                      ; 180010DEC u=
256. 8
257. 0 ; 1WAY-BLOCK 257 INBOUNDS: 4 OUTBOUNDS: 3 [START=180010DF1 END=180010E11] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
257. 0 ; USE: 1802847D8.8
257. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+368.8
257. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
257. 0 xor    $n0x72.8, #0x72.8, rax.8 ; 180010DF8 u=1802847D8.8 d=rax.8
257. 1 mov    #0.1, cf.1              ; 180010DF8 u=           d=cf.1
257. 2 mov    #0.1, of.1              ; 180010DF8 u=           d=of.1
257. 3 setz   ($n0x72.8 ^ #0x72.8), #0.8, zf.1 ; 180010DF8 u=1802847D8.8 d=zf.1
257. 4 setp   ($n0x72.8 ^ #0x72.8), #0.8, pf.1 ; 180010DF8 u=1802847D8.8 d=pf.1
257. 5 sets   $n0x72.8, sf.1          ; 180010DF8 u=1802847D8.8 d=sf.1
257. 6 xor    $n0x72.8, #0x72.8, %var_570.8 ; 180010DFC u=1802847D8.8 d=sp+368.8
257. 7 mov    #0x30.4, %var_8A8.4     ; 180010E04 u=           d=sp+30.4
257. 8 goto   @3                      ; 180010E0C u=
257. 8
258. 0 ; 1WAY-BLOCK 258 INBOUNDS: 4 OUTBOUNDS: 259 [START=180010E11 END=180010E3E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
258. 0 ; USE: rsp.8,sp+5B0.8,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..5B0,sp+5B8..,SHADOW,ARGS,GLBHIGH)
258. 0 ; DEF: rax.16,rcx.8,r8.8,r9.8,sp+280.8,(cf.1,zf.1,sf.1,of.1,pf.1,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..280,sp+288..,RET,SHADOW,ARGS,GLBHIGH)
258. 0 mov    %var_328.8, rax.8       ; 180010E11 u=sp+5B0.8   d=rax.8
258. 1 mov    %var_328.8, %var_658.8  ; 180010E19 u=sp+5B0.8   d=sp+280.8
258. 2 add    rsp.8, #0x280.8, r9.8   ; 180010E21 u=rsp.8      d=r9.8
258. 3 mov    #0x5F.8, rcx.8          ; 180010E29 u=           d=rcx.8
258. 4 mov    #0x1A.8, rdx.8          ; 180010E2E u=           d=rdx.8
258. 5 mov    #2.8, r8.8              ; 180010E33 u=           d=r8.8
258. 6 call   $sub_180137D30          ; 180010E39 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
258. 6
259. 0 ; 1WAY-BLOCK 259 INBOUNDS: 258 OUTBOUNDS: 3 [START=180010E3E END=180010E6D] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
259. 0 ; USE: sp+280.8
259. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+5B8.8
259. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
259. 0 xor    %var_658.8, #0xCA.8, rax.8 ; 180010E43 u=sp+280.8   d=rax.8
259. 1 cfadd  (%var_658.8 ^ #0xCA.8), #-0x4581C12A87917C75.8, cf.1 ; 180010E55 u=sp+280.8   d=cf.1
259. 2 ofadd  (%var_658.8 ^ #0xCA.8), #-0x4581C12A87917C75.8, of.1 ; 180010E55 u=sp+280.8   d=of.1
259. 3 setz   (%var_658.8 ^ #0xCA.8), #0x4581C12A87917C75.8, zf.1 ; 180010E55 u=sp+280.8   d=zf.1
259. 4 setp   (%var_658.8 ^ #0xCA.8), #0x4581C12A87917C75.8, pf.1 ; 180010E55 u=sp+280.8   d=pf.1
259. 5 sets   ((%var_658.8 ^ #0xCA.8)-#0x4581C12A87917C75.8), sf.1 ; 180010E55 u=sp+280.8   d=sf.1
259. 6 sub    (%var_658.8 ^ #0xCA.8), #0x4581C12A87917C75.8, rcx.8 ; 180010E55 u=sp+280.8   d=rcx.8
259. 7 sub    (%var_658.8 ^ #0xCA.8), #0x4581C12A87917C75.8, %var_320.8 ; 180010E58 u=sp+280.8   d=sp+5B8.8
259. 8 mov    #0x73.4, %var_8A8.4     ; 180010E60 u=           d=sp+30.4
259. 9 goto   @3                      ; 180010E68 u=
259. 9
260. 0 ; 1WAY-BLOCK 260 INBOUNDS: 4 OUTBOUNDS: 261 [START=180010E6D END=180010EE9] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
260. 0 ; USE: rsp.8,(rax.8,rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH)
260. 0 ; DEF: rdx.8,rcx.8,r8.8,r9.8,(cf.1,zf.1,sf.1,of.1,pf.1,rax.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
260. 0 add    rsp.8, #0xB0.8, rdx.8   ; 180010ECB u=rsp.8      d=rdx.8
260. 1 mov    #0x26.8, rcx.8          ; 180010ED3 u=           d=rcx.8
260. 2 mov    #0x14.8, r8.8           ; 180010ED8 u=           d=r8.8
260. 3 mov    #0xC.8, r9.8            ; 180010EDE u=           d=r9.8
260. 4 call   $sub_1800D0EB0          ; 180010EE4 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
260. 4
261. 0 ; 1WAY-BLOCK 261 INBOUNDS: 260 OUTBOUNDS: 3 [START=180010EE9 END=180010F47] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
261. 0 ; USE: sp+B0.4
261. 0 ; DEF: rax.8,sp+30.4,sp+1AC.4
261. 0 ; DNU: rax.8
261. 0 xdu    %var_828.4, rax.8       ; 180010EE9 u=sp+B0.4    d=rax.8
261. 1 mov    %var_828.4, %var_72C.4  ; 180010EF0 u=sp+B0.4    d=sp+1AC.4
261. 2 mov    #0x95.4, %var_8A8.4     ; 180010F3A u=           d=sp+30.4
261. 3 goto   @3                      ; 180010F42 u=
261. 3
262. 0 ; 1WAY-BLOCK 262 INBOUNDS: 4 OUTBOUNDS: 3 [START=180010F47 END=180010FC8] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
262. 0 ; USE: ds.2,sp+47.1,sp+3A8..3B8,(GLBLOW,sp+0..47,sp+48..3A8,sp+3B8..,SHADOW,ARGS,GLBHIGH)
262. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+3B8..3C8
262. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
262. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 180010F4F u=           d=rcx.8
262. 1 mov    #0.1, cf.1              ; 180010F5A u=           d=cf.1
262. 2 mov    #0.1, of.1              ; 180010F5A u=           d=of.1
262. 3 setz   (%var_530.8 | xdu.8([ds.2:(%var_528.8+&($p_InLoadOrderModuleList_5).8)].1)), #0.8, zf.1 ; 180010F5A u=ds.2,sp+3A8..3B8,(GLBLOW,sp+0..3A8,sp+3B8..,SHADOW,ARGS,GLBHIGH) d=zf.1
262. 4 setp   (%var_530.8 | xdu.8([ds.2:(%var_528.8+&($p_InLoadOrderModuleList_5).8)].1)), #0.8, pf.1 ; 180010F5A u=ds.2,sp+3A8..3B8,(GLBLOW,sp+0..3A8,sp+3B8..,SHADOW,ARGS,GLBHIGH) d=pf.1
262. 5 sets   (%var_530.8 | xdu.8([ds.2:(%var_528.8+&($p_InLoadOrderModuleList_5).8)].1)), sf.1 ; 180010F5A u=ds.2,sp+3A8..3B8,(GLBLOW,sp+0..3A8,sp+3B8..,SHADOW,ARGS,GLBHIGH) d=sf.1
262. 6 or     %var_530.8, xdu.8([ds.2:(%var_528.8+&($p_InLoadOrderModuleList_5).8)].1), %var_520.8 ; 180010F62 u=ds.2,sp+3A8..3B8,(GLBLOW,sp+0..3A8,sp+3B8..,SHADOW,ARGS,GLBHIGH) d=sp+3B8.8
262. 7 xdu    %var_898@7.1, rax.8     ; 180010FAE u=sp+47.1    d=rax.8
262. 8 xdu    %var_898@7.1, %var_518.8 ; 180010FB3 u=sp+47.1    d=sp+3C0.8
262. 9 mov    #0x38.4, %var_8A8.4     ; 180010FBB u=           d=sp+30.4
262.10 goto   @3                      ; 180010FC3 u=
262.10
263. 0 ; 1WAY-BLOCK 263 INBOUNDS: 4 OUTBOUNDS: 3 [START=180010FC8 END=180011040] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
263. 0 ; USE: sp+F4.4
263. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+F8.4
263. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
263. 0 setz   (%var_7E4.4 ^ #0x1D51E806.4), #0x1A57E050.4, zf.1 ; 180010FD4 u=sp+F4.4    d=zf.1
263. 1 setp   (%var_7E4.4 ^ #0x1D51E806.4), #0x1A57E050.4, pf.1 ; 180010FD4 u=sp+F4.4    d=pf.1
263. 2 sets   ((%var_7E4.4 ^ #0x1D51E806.4)-#0x1A57E050.4), sf.1 ; 180010FD4 u=sp+F4.4    d=sf.1
263. 3 sub    (%var_7E4.4 ^ #0x1D51E806.4), #0x1A57E050.4, eax.4 ; 180010FD4 u=sp+F4.4    d=eax.4
263. 4 cfshl  eax.4, #1.1, tt.1       ; 180010FD9 u=eax.4      d=tt.1
263. 5 mov    call !__ROL4__<fast:_DWORD eax.4,char #1.1>.4, eax.4 ; 180010FD9 u=eax.4      d=eax.4
263. 6 mov    tt.1, cf.1              ; 180010FD9 u=tt.1       d=cf.1
263. 7 und    of.1                    ; 180010FD9 u=           d=of.1
263. 8 xdu    eax.4, rax.8            ; 180010FD9 u=eax.4      d=rax^4.4
263. 9 mov    eax.4, %var_7E0.4       ; 180010FDB u=eax.4      d=sp+F8.4
263.10 mov    #0xA.4, %var_8A8.4      ; 180011033 u=           d=sp+30.4
263.11 goto   @3                      ; 18001103B u=
263.11
264. 0 ; 1WAY-BLOCK 264 INBOUNDS: 4 OUTBOUNDS: 3 [START=180011040 END=18001107E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
264. 0 ; USE: ds.2,sp+410.1,sp+418..428,(GLBLOW,sp+0..410,sp+411.7,sp+428..,SHADOW,ARGS,GLBHIGH)
264. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+428..438
264. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
264. 0 or     %var_4C0.8, xdu.8((#0x100.4*xdu.4([ds.2:%var_4B8.8].1))), %var_4B0.8 ; 180011056 u=ds.2,sp+418..428,(GLBLOW,sp+0..418,sp+428..,SHADOW,ARGS,GLBHIGH) d=sp+428.8
264. 1 mov    #0.1, cf.1              ; 180011066 u=           d=cf.1
264. 2 mov    #0.1, of.1              ; 180011066 u=           d=of.1
264. 3 setz   xdu.4((%var_4C8.1 & #0xF.1)), #0.4, zf.1 ; 180011066 u=sp+410.1   d=zf.1
264. 4 setp   xdu.4((%var_4C8.1 & #0xF.1)), #0.4, pf.1 ; 180011066 u=sp+410.1   d=pf.1
264. 5 mov    #0.1, sf.1              ; 180011066 u=           d=sf.1
264. 6 xdu    (%var_4C8.1 & #0xF.1), rax.8 ; 180011066 u=sp+410.1   d=rax.8
264. 7 xdu    (%var_4C8.1 & #0xF.1), %var_4A8.8 ; 180011069 u=sp+410.1   d=sp+430.8
264. 8 mov    #0x42.4, %var_8A8.4     ; 180011071 u=           d=sp+30.4
264. 9 goto   @3                      ; 180011079 u=
264. 9
265. 0 ; 1WAY-BLOCK 265 INBOUNDS: 4 OUTBOUNDS: 3 [START=18001107E END=18001110B] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
265. 0 ; USE: r12.8,sp+448.8,180281B27.8
265. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+450.8
265. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
265. 0 xor    r12.8, (%var_490.8 ^ $qword_180281B27.8), rax.8 ; 18001108D u=r12.8,sp+448.8,180281B27.8 d=rax.8
265. 1 mov    #0.1, cf.1              ; 18001108D u=           d=cf.1
265. 2 mov    #0.1, of.1              ; 18001108D u=           d=of.1
265. 3 setz   (r12.8 ^ (%var_490.8 ^ $qword_180281B27.8)), #0.8, zf.1 ; 18001108D u=r12.8,sp+448.8,180281B27.8 d=zf.1
265. 4 setp   (r12.8 ^ (%var_490.8 ^ $qword_180281B27.8)), #0.8, pf.1 ; 18001108D u=r12.8,sp+448.8,180281B27.8 d=pf.1
265. 5 sets   (r12.8 ^ (%var_490.8 ^ $qword_180281B27.8)), sf.1 ; 18001108D u=r12.8,sp+448.8,180281B27.8 d=sf.1
265. 6 xor    r12.8, (%var_490.8 ^ $qword_180281B27.8), %var_488.8 ; 180011090 u=r12.8,sp+448.8,180281B27.8 d=sp+450.8
265. 7 mov    #0x46.4, %var_8A8.4     ; 1800110FE u=           d=sp+30.4
265. 8 goto   @3                      ; 180011106 u=
265. 8
266. 0 ; 1WAY-BLOCK 266 INBOUNDS: 4 OUTBOUNDS: 3 [START=18001110B END=18001112F] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
266. 0 ; USE: ds.2,sp+4B.1,(GLBLOW,sp+0..4B,sp+4C..,SHADOW,ARGS,GLBHIGH)
266. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+4C.1
266. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^1.7,rcx.8
266. 0 mov    &($p_InLoadOrderModuleList_8).8, rcx.8 ; 180011110 u=           d=rcx.8
266. 1 xdu    [ds.2:(xdu.8(%var_88D.1)+&($p_InLoadOrderModuleList_8).8)].1, rax.8 ; 180011117 u=ds.2,sp+4B.1,(GLBLOW,sp+0..4B,sp+4C..,SHADOW,ARGS,GLBHIGH) d=rax.8
266. 2 cfshl  al.1, #4.1, cf.1        ; 18001111B u=al.1       d=cf.1
266. 3 mul    #0x10.1, al.1, al.1     ; 18001111B u=al.1       d=al.1
266. 4 und    of.1                    ; 18001111B u=           d=of.1
266. 5 setz   al.1, #0.1, zf.1        ; 18001111B u=al.1       d=zf.1
266. 6 setp   al.1, #0.1, pf.1        ; 18001111B u=al.1       d=pf.1
266. 7 sets   al.1, sf.1              ; 18001111B u=al.1       d=sf.1
266. 8 mov    al.1, %var_88C.1        ; 18001111E u=al.1       d=sp+4C.1
266. 9 mov    #6.4, %var_8A8.4        ; 180011122 u=           d=sp+30.4
266.10 goto   @3                      ; 18001112A u=
266.10
267. 0 ; 1WAY-BLOCK 267 INBOUNDS: 4 OUTBOUNDS: 3 [START=18001112F END=180011163] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
267. 0 ; USE: ds.2,sp+3D8.8,sp+3E8.8,(GLBLOW,sp+0..3D8,sp+3E0.8,sp+3F0..,SHADOW,ARGS,GLBHIGH)
267. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+3F0.8
267. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
267. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 180011137 u=           d=rcx.8
267. 1 or     %var_500.8, (#0x1000000000.8*xdu.8([ds.2:(%var_4F0.8+&($p_InLoadOrderModuleList_5).8)].1)), rax.8 ; 180011146 u=ds.2,sp+3D8.8,sp+3E8.8,(GLBLOW,sp+0..3D8,sp+3E0.8,sp+3F0..,SHADOW,ARGS,GLBHIGH) d=rax.8
267. 2 mov    #0.1, cf.1              ; 180011146 u=           d=cf.1
267. 3 mov    #0.1, of.1              ; 180011146 u=           d=of.1
267. 4 setz   (%var_500.8 | (#0x1000000000.8*xdu.8([ds.2:(%var_4F0.8+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, zf.1 ; 180011146 u=ds.2,sp+3D8.8,sp+3E8.8,(GLBLOW,sp+0..3D8,sp+3E0.8,sp+3F0..,SHADOW,ARGS,GLBHIGH) d=zf.1
267. 5 setp   (%var_500.8 | (#0x1000000000.8*xdu.8([ds.2:(%var_4F0.8+&($p_InLoadOrderModuleList_5).8)].1))), #0.8, pf.1 ; 180011146 u=ds.2,sp+3D8.8,sp+3E8.8,(GLBLOW,sp+0..3D8,sp+3E0.8,sp+3F0..,SHADOW,ARGS,GLBHIGH) d=pf.1
267. 6 sets   (%var_500.8 | (#0x1000000000.8*xdu.8([ds.2:(%var_4F0.8+&($p_InLoadOrderModuleList_5).8)].1))), sf.1 ; 180011146 u=ds.2,sp+3D8.8,sp+3E8.8,(GLBLOW,sp+0..3D8,sp+3E0.8,sp+3F0..,SHADOW,ARGS,GLBHIGH) d=sf.1
267. 7 or     %var_500.8, (#0x1000000000.8*xdu.8([ds.2:(%var_4F0.8+&($p_InLoadOrderModuleList_5).8)].1)), %var_4E8.8 ; 18001114E u=ds.2,sp+3D8.8,sp+3E8.8,(GLBLOW,sp+0..3D8,sp+3E0.8,sp+3F0..,SHADOW,ARGS,GLBHIGH) d=sp+3F0.8
267. 8 mov    #0x3C.4, %var_8A8.4     ; 180011156 u=           d=sp+30.4
267. 9 goto   @3                      ; 18001115E u=
267. 9
268. 0 ; 1WAY-BLOCK 268 INBOUNDS: 4 OUTBOUNDS: 3 [START=180011163 END=1800111F8] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
268. 0 ; USE: sp+40.1,sp+55.1,sp+3A0.8
268. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+3A8..3B8
268. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8
268. 0 or     %var_538.8, xdu.8((#0x100000.4*xdu.4(%var_883.1))), %var_530.8 ; 1800111D3 u=sp+55.1,sp+3A0.8 d=sp+3A8.8
268. 1 mov    #0.1, cf.1              ; 1800111E0 u=           d=cf.1
268. 2 mov    #0.1, of.1              ; 1800111E0 u=           d=of.1
268. 3 setz   xdu.4((%var_898.1 & #0xF.1)), #0.4, zf.1 ; 1800111E0 u=sp+40.1    d=zf.1
268. 4 setp   xdu.4((%var_898.1 & #0xF.1)), #0.4, pf.1 ; 1800111E0 u=sp+40.1    d=pf.1
268. 5 mov    #0.1, sf.1              ; 1800111E0 u=           d=sf.1
268. 6 xdu    (%var_898.1 & #0xF.1), rax.8 ; 1800111E0 u=sp+40.1    d=rax.8
268. 7 xdu    (%var_898.1 & #0xF.1), %var_528.8 ; 1800111E3 u=sp+40.1    d=sp+3B0.8
268. 8 mov    #0x37.4, %var_8A8.4     ; 1800111EB u=           d=sp+30.4
268. 9 goto   @3                      ; 1800111F3 u=
268. 9
269. 0 ; 1WAY-BLOCK 269 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800111F8 END=18001122C] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
269. 0 ; USE: sp+4E.2,(sp+50.1)
269. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+50.1,sp+2F0.8
269. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
269. 0 xor    (%var_889.1 ^ %var_88A.1), #0x79.1, %var_888.1 ; 180011203 u=sp+4E.2    d=sp+50.1
269. 1 xdu    (xdu.4(%var_888.1) >>l #4.1), rax.8 ; 18001120A u=sp+50.1    d=rax.8
269. 2 cfadd  rax.8, &($byte_1802272E0).8, cf.1 ; 180011214 u=rax.8      d=cf.1
269. 3 ofadd  rax.8, &($byte_1802272E0).8, of.1 ; 180011214 u=rax.8      d=of.1
269. 4 setz   (rax.8+&($byte_1802272E0).8), #0.8, zf.1 ; 180011214 u=rax.8      d=zf.1
269. 5 setp   (rax.8+&($byte_1802272E0).8), #0.8, pf.1 ; 180011214 u=rax.8      d=pf.1
269. 6 sets   (rax.8+&($byte_1802272E0).8), sf.1 ; 180011214 u=rax.8      d=sf.1
269. 7 add    rax.8, &($byte_1802272E0).8, rcx.8 ; 180011214 u=rax.8      d=rcx.8
269. 8 add    rax.8, &($byte_1802272E0).8, %var_5E8.8 ; 180011217 u=rax.8      d=sp+2F0.8
269. 9 mov    #0xE.4, %var_8A8.4      ; 18001121F u=           d=sp+30.4
269.10 goto   @3                      ; 180011227 u=
269.10
270. 0 ; 1WAY-BLOCK 270 INBOUNDS: 4 OUTBOUNDS: 3 [START=18001122C END=1800112D3] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
270. 0 ; USE: ds.2,sp+380.1,sp+3F0.8,(GLBLOW,sp+0..380,sp+381..3F0,sp+3F8..,SHADOW,ARGS,GLBHIGH)
270. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+3F8.8
270. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
270. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 180011237 u=           d=rcx.8
270. 1 or     %var_4E8.8, xdu.8((#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_558.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), rax.8 ; 1800112B6 u=ds.2,sp+380.1,sp+3F0.8,(GLBLOW,sp+0..380,sp+381..3F0,sp+3F8..,SHADOW,ARGS,GLBHIGH) d=rax.8
270. 2 mov    #0.1, cf.1              ; 1800112B6 u=           d=cf.1
270. 3 mov    #0.1, of.1              ; 1800112B6 u=           d=of.1
270. 4 setz   (%var_4E8.8 | xdu.8((#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_558.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)))), #0.8, zf.1 ; 1800112B6 u=ds.2,sp+380.1,sp+3F0.8,(GLBLOW,sp+0..380,sp+381..3F0,sp+3F8..,SHADOW,ARGS,GLBHIGH) d=zf.1
270. 5 setp   (%var_4E8.8 | xdu.8((#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_558.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)))), #0.8, pf.1 ; 1800112B6 u=ds.2,sp+380.1,sp+3F0.8,(GLBLOW,sp+0..380,sp+381..3F0,sp+3F8..,SHADOW,ARGS,GLBHIGH) d=pf.1
270. 6 sets   (%var_4E8.8 | xdu.8((#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_558.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)))), sf.1 ; 1800112B6 u=ds.2,sp+380.1,sp+3F0.8,(GLBLOW,sp+0..380,sp+381..3F0,sp+3F8..,SHADOW,ARGS,GLBHIGH) d=sf.1
270. 7 or     %var_4E8.8, xdu.8((#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_558.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1))), %var_4E0.8 ; 1800112BE u=ds.2,sp+380.1,sp+3F0.8,(GLBLOW,sp+0..380,sp+381..3F0,sp+3F8..,SHADOW,ARGS,GLBHIGH) d=sp+3F8.8
270. 8 mov    #0x3D.4, %var_8A8.4     ; 1800112C6 u=           d=sp+30.4
270. 9 goto   @3                      ; 1800112CE u=
270. 9
271. 0 ; 1WAY-BLOCK 271 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800112D3 END=180011402] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
271. 0 ; DEF: sp+30.4
271. 0 mov    #0x23.4, %var_8A8.4     ; 1800113F5 u=           d=sp+30.4
271. 1 goto   @3                      ; 1800113FD u=
271. 1
272. 0 ; 1WAY-BLOCK 272 INBOUNDS: 4 OUTBOUNDS: 273 [START=180011402 END=180011495] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
272. 0 ; USE: rsp.8,sp+164.4,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..164,sp+168..,SHADOW,ARGS,GLBHIGH)
272. 0 ; DEF: rax.16,rcx.8,r8.8,r9.8,sp+AC.4,(cf.1,zf.1,sf.1,of.1,pf.1,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..AC,sp+B0..,RET,SHADOW,ARGS,GLBHIGH)
272. 0 xdu    %var_774.4, rax.8       ; 180011402 u=sp+164.4   d=rax.8
272. 1 mov    %var_774.4, %var_82C.4  ; 180011409 u=sp+164.4   d=sp+AC.4
272. 2 add    rsp.8, #0xAC.8, rdx.8   ; 180011477 u=rsp.8      d=rdx.8
272. 3 mov    #0xB.8, rcx.8           ; 18001147F u=           d=rcx.8
272. 4 mov    #0xB.8, r8.8            ; 180011484 u=           d=r8.8
272. 5 mov    #0x37.8, r9.8           ; 18001148A u=           d=r9.8
272. 6 call   $sub_1800769A0          ; 180011490 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
272. 6
273. 0 ; 1WAY-BLOCK 273 INBOUNDS: 272 OUTBOUNDS: 3 [START=180011495 END=1800114B0] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
273. 0 ; USE: sp+AC.4
273. 0 ; DEF: rax.8,sp+30.4,sp+168.4
273. 0 ; DNU: rax.8
273. 0 xdu    %var_82C.4, rax.8       ; 180011495 u=sp+AC.4    d=rax.8
273. 1 mov    %var_82C.4, %var_770.4  ; 18001149C u=sp+AC.4    d=sp+168.4
273. 2 mov    #0x6C.4, %var_8A8.4     ; 1800114A3 u=           d=sp+30.4
273. 3 goto   @3                      ; 1800114AB u=
273. 3
274. 0 ; 1WAY-BLOCK 274 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800114B0 END=18001153E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
274. 0 ; USE: ds.2,sp+120.4,sp+320.1,(GLBLOW,sp+0..120,sp+124..320,sp+321..,SHADOW,ARGS,GLBHIGH)
274. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+124.4
274. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
274. 0 mov    &($p_InLoadOrderModuleList_10).8, rcx.8 ; 1800114BB u=           d=rcx.8
274. 1 mov    #0.1, cf.1              ; 1800114C9 u=           d=cf.1
274. 2 mov    #0.1, of.1              ; 1800114C9 u=           d=of.1
274. 3 setz   (%var_7B8.4 | (#0x100000.4*xdu.4([ds.2:(xdu.8((%var_5B8.1 & #0xF.1))+&($p_InLoadOrderModuleList_10).8)].1))), #0.4, zf.1 ; 1800114C9 u=ds.2,sp+120.4,sp+320.1,(GLBLOW,sp+0..120,sp+124..320,sp+321..,SHADOW,ARGS,GLBHIGH) d=zf.1
274. 4 setp   (%var_7B8.4 | (#0x100000.4*xdu.4([ds.2:(xdu.8((%var_5B8.1 & #0xF.1))+&($p_InLoadOrderModuleList_10).8)].1))), #0.4, pf.1 ; 1800114C9 u=ds.2,sp+120.4,sp+320.1,(GLBLOW,sp+0..120,sp+124..320,sp+321..,SHADOW,ARGS,GLBHIGH) d=pf.1
274. 5 sets   (%var_7B8.4 | (#0x100000.4*xdu.4([ds.2:(xdu.8((%var_5B8.1 & #0xF.1))+&($p_InLoadOrderModuleList_10).8)].1))), sf.1 ; 1800114C9 u=ds.2,sp+120.4,sp+320.1,(GLBLOW,sp+0..120,sp+124..320,sp+321..,SHADOW,ARGS,GLBHIGH) d=sf.1
274. 6 xdu    (%var_7B8.4 | (#0x100000.4*xdu.4([ds.2:(xdu.8((%var_5B8.1 & #0xF.1))+&($p_InLoadOrderModuleList_10).8)].1))), rax.8 ; 1800114C9 u=ds.2,sp+120.4,sp+320.1,(GLBLOW,sp+0..120,sp+124..320,sp+321..,SHADOW,ARGS,GLBHIGH) d=rax.8
274. 7 or     %var_7B8.4, (#0x100000.4*xdu.4([ds.2:(xdu.8((%var_5B8.1 & #0xF.1))+&($p_InLoadOrderModuleList_10).8)].1)), %var_7B4.4 ; 1800114D0 u=ds.2,sp+120.4,sp+320.1,(GLBLOW,sp+0..120,sp+124..320,sp+321..,SHADOW,ARGS,GLBHIGH) d=sp+124.4
274. 8 mov    #0x1D.4, %var_8A8.4     ; 180011531 u=           d=sp+30.4
274. 9 goto   @3                      ; 180011539 u=
274. 9
275. 0 ; 1WAY-BLOCK 275 INBOUNDS: 4 OUTBOUNDS: 3 [START=18001153E END=18001156A] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
275. 0 ; USE: ds.2,sp+67.1,(GLBLOW,sp+0..67,sp+68..,SHADOW,ARGS,GLBHIGH)
275. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+4B8.8
275. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
275. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 180011546 u=           d=rcx.8
275. 1 xdu    [ds.2:(xdu.8((%var_878@7.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1, rax.8 ; 18001154D u=ds.2,sp+67.1,(GLBLOW,sp+0..67,sp+68..,SHADOW,ARGS,GLBHIGH) d=rax.8
275. 2 cfshl  rax.8, #0x38.1, cf.1    ; 180011551 u=rax.8      d=cf.1
275. 3 mul    #0x100000000000000.8, rax.8, rax.8 ; 180011551 u=rax.8      d=rax.8
275. 4 und    of.1                    ; 180011551 u=           d=of.1
275. 5 setz   rax.8, #0.8, zf.1       ; 180011551 u=rax.8      d=zf.1
275. 6 setp   rax.8, #0.8, pf.1       ; 180011551 u=rax.8      d=pf.1
275. 7 sets   rax.8, sf.1             ; 180011551 u=rax.8      d=sf.1
275. 8 mov    rax.8, %var_420.8       ; 180011555 u=rax.8      d=sp+4B8.8
275. 9 mov    #0x54.4, %var_8A8.4     ; 18001155D u=           d=sp+30.4
275.10 goto   @3                      ; 180011565 u=
275.10
276. 0 ; 1WAY-BLOCK 276 INBOUNDS: 4 OUTBOUNDS: 3 [START=18001156A END=1800115EE] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
276. 0 ; USE: sp+468.1,sp+4F8..508
276. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+508..518
276. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
276. 0 or     %var_3E0.8, (#0x10.8*%var_3D8.8), %var_3D0.8 ; 18001157E u=sp+4F8..508 d=sp+508.8
276. 1 xdu    (%var_470.1 & #0xF.1), rax.8 ; 1800115CC u=sp+468.1   d=rax.8
276. 2 cfadd  rax.8, &($p_InLoadOrderModuleList_5).8, cf.1 ; 1800115D6 u=rax.8      d=cf.1
276. 3 ofadd  rax.8, &($p_InLoadOrderModuleList_5).8, of.1 ; 1800115D6 u=rax.8      d=of.1
276. 4 setz   (rax.8+&($p_InLoadOrderModuleList_5).8), #0.8, zf.1 ; 1800115D6 u=rax.8      d=zf.1
276. 5 setp   (rax.8+&($p_InLoadOrderModuleList_5).8), #0.8, pf.1 ; 1800115D6 u=rax.8      d=pf.1
276. 6 sets   (rax.8+&($p_InLoadOrderModuleList_5).8), sf.1 ; 1800115D6 u=rax.8      d=sf.1
276. 7 add    rax.8, &($p_InLoadOrderModuleList_5).8, rcx.8 ; 1800115D6 u=rax.8      d=rcx.8
276. 8 add    rax.8, &($p_InLoadOrderModuleList_5).8, %var_3C8.8 ; 1800115D9 u=rax.8      d=sp+510.8
276. 9 mov    #0x5A.4, %var_8A8.4     ; 1800115E1 u=           d=sp+30.4
276.10 goto   @3                      ; 1800115E9 u=
276.10
277. 0 ; 1WAY-BLOCK 277 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800115EE END=18001163F] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
277. 0 ; USE: ds.2,sp+D8.8,sp+138.4,sp+340.8,(GLBLOW,sp+0..D8,sp+E0..138,sp+13C..340,sp+348..,SHADOW,ARGS,GLBHIGH)
277. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+13C.4,sp+348..358
277. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
277. 0 or     %var_7A0.4, xdu.4([ds.2:(%var_598.8+&($p_InLoadOrderModuleList_1).8)].1), %var_79C.4 ; 180011608 u=ds.2,sp+138.4,sp+340.8,(GLBLOW,sp+0..138,sp+13C..340,sp+348..,SHADOW,ARGS,GLBHIGH) d=sp+13C.4
277. 1 shr    %var_800.8, #0x10.1, rcx.8 ; 18001161A u=sp+D8.8    d=rcx.8
277. 2 shr    %var_800.8, #0x10.1, %var_590.8 ; 18001161E u=sp+D8.8    d=sp+348.8
277. 3 cfshr  %var_800.8, #0x14.1, cf.1 ; 180011626 u=sp+D8.8    d=cf.1
277. 4 shr    %var_800.8, #0x14.1, rax.8 ; 180011626 u=sp+D8.8    d=rax.8
277. 5 und    of.1                    ; 180011626 u=           d=of.1
277. 6 setz   (%var_800.8 >>l #0x14.1), #0.8, zf.1 ; 180011626 u=sp+D8.8    d=zf.1
277. 7 setp   (%var_800.8 >>l #0x14.1), #0.8, pf.1 ; 180011626 u=sp+D8.8    d=pf.1
277. 8 mov    #0.1, sf.1              ; 180011626 u=           d=sf.1
277. 9 shr    %var_800.8, #0x14.1, %var_588.8 ; 18001162A u=sp+D8.8    d=sp+350.8
277.10 mov    #0x28.4, %var_8A8.4     ; 180011632 u=           d=sp+30.4
277.11 goto   @3                      ; 18001163A u=
277.11
278. 0 ; 1WAY-BLOCK 278 INBOUNDS: 4 OUTBOUNDS: 3 [START=18001163F END=1800116B8] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
278. 0 ; DEF: sp+30.4
278. 0 mov    #3.4, %var_8A8.4        ; 1800116AB u=           d=sp+30.4
278. 1 goto   @3                      ; 1800116B3 u=
278. 1
279. 0 ; 1WAY-BLOCK 279 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800116B8 END=180011765] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
279. 0 ; USE: sp+60.8,sp+4B0..4C0
279. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+4C0..4D8
279. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
279. 0 or     %var_420.8, %var_428.8, %var_418.8 ; 180011723 u=sp+4B0..4C0 d=sp+4C0.8
279. 1 shr    %var_878.8, #8.1, %var_410.8 ; 180011734 u=sp+60.8    d=sp+4C8.8
279. 2 xdu    (%var_878.2 >>l #0xC.1), rax.8 ; 180011743 u=sp+60.2    d=rax.8
279. 3 cfadd  rax.8, &($p_InLoadOrderModuleList_5).8, cf.1 ; 18001174D u=rax.8      d=cf.1
279. 4 ofadd  rax.8, &($p_InLoadOrderModuleList_5).8, of.1 ; 18001174D u=rax.8      d=of.1
279. 5 setz   (rax.8+&($p_InLoadOrderModuleList_5).8), #0.8, zf.1 ; 18001174D u=rax.8      d=zf.1
279. 6 setp   (rax.8+&($p_InLoadOrderModuleList_5).8), #0.8, pf.1 ; 18001174D u=rax.8      d=pf.1
279. 7 sets   (rax.8+&($p_InLoadOrderModuleList_5).8), sf.1 ; 18001174D u=rax.8      d=sf.1
279. 8 add    rax.8, &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18001174D u=rax.8      d=rcx.8
279. 9 add    rax.8, &($p_InLoadOrderModuleList_5).8, %var_408.8 ; 180011750 u=rax.8      d=sp+4D0.8
279.10 mov    #0x55.4, %var_8A8.4     ; 180011758 u=           d=sp+30.4
279.11 goto   @3                      ; 180011760 u=
279.11
280. 0 ; 1WAY-BLOCK 280 INBOUNDS: 4 OUTBOUNDS: 3 [START=180011765 END=1800117F3] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
280. 0 ; USE: ds.2,sp+60.1,sp+4A8.8,(GLBLOW,sp+0..60,sp+61..4A8,sp+4B0..,SHADOW,ARGS,GLBHIGH)
280. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+4B0.8
280. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
280. 0 mov    &($p_InLoadOrderModuleList_5).8, rcx.8 ; 18001176D u=           d=rcx.8
280. 1 or     %var_430.8, xdu.8([ds.2:(xdu.8((%var_878.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1), rax.8 ; 180011778 u=ds.2,sp+60.1,sp+4A8.8,(GLBLOW,sp+0..60,sp+61..4A8,sp+4B0..,SHADOW,ARGS,GLBHIGH) d=rax.8
280. 2 mov    #0.1, cf.1              ; 180011778 u=           d=cf.1
280. 3 mov    #0.1, of.1              ; 180011778 u=           d=of.1
280. 4 setz   (%var_430.8 | xdu.8([ds.2:(xdu.8((%var_878.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)), #0.8, zf.1 ; 180011778 u=ds.2,sp+60.1,sp+4A8.8,(GLBLOW,sp+0..60,sp+61..4A8,sp+4B0..,SHADOW,ARGS,GLBHIGH) d=zf.1
280. 5 setp   (%var_430.8 | xdu.8([ds.2:(xdu.8((%var_878.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)), #0.8, pf.1 ; 180011778 u=ds.2,sp+60.1,sp+4A8.8,(GLBLOW,sp+0..60,sp+61..4A8,sp+4B0..,SHADOW,ARGS,GLBHIGH) d=pf.1
280. 6 sets   (%var_430.8 | xdu.8([ds.2:(xdu.8((%var_878.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1)), sf.1 ; 180011778 u=ds.2,sp+60.1,sp+4A8.8,(GLBLOW,sp+0..60,sp+61..4A8,sp+4B0..,SHADOW,ARGS,GLBHIGH) d=sf.1
280. 7 or     %var_430.8, xdu.8([ds.2:(xdu.8((%var_878.1 & #0xF.1))+&($p_InLoadOrderModuleList_5).8)].1), %var_428.8 ; 180011780 u=ds.2,sp+60.1,sp+4A8.8,(GLBLOW,sp+0..60,sp+61..4A8,sp+4B0..,SHADOW,ARGS,GLBHIGH) d=sp+4B0.8
280. 8 mov    #0x53.4, %var_8A8.4     ; 1800117E6 u=           d=sp+30.4
280. 9 goto   @3                      ; 1800117EE u=
280. 9
281. 0 ; 1WAY-BLOCK 281 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800117F3 END=180011816] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
281. 0 ; USE: sp+108.4
281. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+10C.4
281. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^4.4
281. 0 mov    call !__ROL4__<fast:_DWORD %var_7D0.4,char #0xC.1>.4, eax.4 ; 1800117FA u=sp+108.4   d=eax.4
281. 1 xor    eax.4, #0x1445306A.4, eax.4 ; 1800117FD u=eax.4      d=eax.4
281. 2 mov    #0.1, cf.1              ; 1800117FD u=           d=cf.1
281. 3 mov    #0.1, of.1              ; 1800117FD u=           d=of.1
281. 4 setz   eax.4, #0.4, zf.1       ; 1800117FD u=eax.4      d=zf.1
281. 5 setp   eax.4, #0.4, pf.1       ; 1800117FD u=eax.4      d=pf.1
281. 6 sets   eax.4, sf.1             ; 1800117FD u=eax.4      d=sf.1
281. 7 xdu    eax.4, rax.8            ; 1800117FD u=eax.4      d=rax^4.4
281. 8 mov    eax.4, %var_7CC.4       ; 180011802 u=eax.4      d=sp+10C.4
281. 9 mov    #0x16.4, %var_8A8.4     ; 180011809 u=           d=sp+30.4
281.10 goto   @3                      ; 180011811 u=
281.10
282. 0 ; 1WAY-BLOCK 282 INBOUNDS: 4 OUTBOUNDS: 3 [START=180011816 END=18001183E] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
282. 0 ; USE: ds.2,sp+3A.1,sp+4C.1,(GLBLOW,sp+0..3A,sp+3B..4C,sp+4D..,SHADOW,ARGS,GLBHIGH)
282. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,sp+30.4,sp+4D.1
282. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rdx.8,rcx.8
282. 0 xdu    (%var_89E.1 & #0xF.1), rax.8 ; 18001181B u=sp+3A.1    d=rax.8
282. 1 mov    &($p_InLoadOrderModuleList_8).8, rcx.8 ; 18001181E u=           d=rcx.8
282. 2 xdu    %var_88C.1, rdx.8       ; 180011825 u=sp+4C.1    d=rdx.8
282. 3 or     [ds.2:(rax.8+&($p_InLoadOrderModuleList_8).8)].1, %var_88C.1, dl.1 ; 18001182A u=rax.8,ds.2,sp+4C.1,(GLBLOW,sp+0..4C,sp+4D..,SHADOW,ARGS,GLBHIGH) d=dl.1
282. 4 mov    #0.1, cf.1              ; 18001182A u=           d=cf.1
282. 5 mov    #0.1, of.1              ; 18001182A u=           d=of.1
282. 6 setz   ([ds.2:(rax.8+&($p_InLoadOrderModuleList_8).8)].1 | %var_88C.1), #0.1, zf.1 ; 18001182A u=rax.8,ds.2,sp+4C.1,(GLBLOW,sp+0..4C,sp+4D..,SHADOW,ARGS,GLBHIGH) d=zf.1
282. 7 setp   ([ds.2:(rax.8+&($p_InLoadOrderModuleList_8).8)].1 | %var_88C.1), #0.1, pf.1 ; 18001182A u=rax.8,ds.2,sp+4C.1,(GLBLOW,sp+0..4C,sp+4D..,SHADOW,ARGS,GLBHIGH) d=pf.1
282. 8 sets   ([ds.2:(rax.8+&($p_InLoadOrderModuleList_8).8)].1 | %var_88C.1), sf.1 ; 18001182A u=rax.8,ds.2,sp+4C.1,(GLBLOW,sp+0..4C,sp+4D..,SHADOW,ARGS,GLBHIGH) d=sf.1
282. 9 or     [ds.2:(rax.8+&($p_InLoadOrderModuleList_8).8)].1, %var_88C.1, %var_88B.1 ; 18001182D u=rax.8,ds.2,sp+4C.1,(GLBLOW,sp+0..4C,sp+4D..,SHADOW,ARGS,GLBHIGH) d=sp+4D.1
282.10 mov    #7.4, %var_8A8.4        ; 180011831 u=           d=sp+30.4
282.11 goto   @3                      ; 180011839 u=
282.11
283. 0 ; 1WAY-BLOCK 283 INBOUNDS: 4 OUTBOUNDS: 3 [START=18001183E END=1800118D8] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
283. 0 ; USE: ds.2,sp+124.4,sp+308.1,(GLBLOW,sp+0..124,sp+128..308,sp+309..,SHADOW,ARGS,GLBHIGH)
283. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+128.4
283. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8
283. 0 mov    &($p_InLoadOrderModuleList_10).8, rcx.8 ; 180011849 u=           d=rcx.8
283. 1 mov    #0.1, cf.1              ; 1800118BD u=           d=cf.1
283. 2 mov    #0.1, of.1              ; 1800118BD u=           d=of.1
283. 3 setz   (%var_7B4.4 | (#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_5D0.1 & #0xF.1))+&($p_InLoadOrderModuleList_10).8)].1))), #0.4, zf.1 ; 1800118BD u=ds.2,sp+124.4,sp+308.1,(GLBLOW,sp+0..124,sp+128..308,sp+309..,SHADOW,ARGS,GLBHIGH) d=zf.1
283. 4 setp   (%var_7B4.4 | (#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_5D0.1 & #0xF.1))+&($p_InLoadOrderModuleList_10).8)].1))), #0.4, pf.1 ; 1800118BD u=ds.2,sp+124.4,sp+308.1,(GLBLOW,sp+0..124,sp+128..308,sp+309..,SHADOW,ARGS,GLBHIGH) d=pf.1
283. 5 sets   (%var_7B4.4 | (#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_5D0.1 & #0xF.1))+&($p_InLoadOrderModuleList_10).8)].1))), sf.1 ; 1800118BD u=ds.2,sp+124.4,sp+308.1,(GLBLOW,sp+0..124,sp+128..308,sp+309..,SHADOW,ARGS,GLBHIGH) d=sf.1
283. 6 xdu    (%var_7B4.4 | (#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_5D0.1 & #0xF.1))+&($p_InLoadOrderModuleList_10).8)].1))), rax.8 ; 1800118BD u=ds.2,sp+124.4,sp+308.1,(GLBLOW,sp+0..124,sp+128..308,sp+309..,SHADOW,ARGS,GLBHIGH) d=rax.8
283. 7 or     %var_7B4.4, (#0x1000000.4*xdu.4([ds.2:(xdu.8((%var_5D0.1 & #0xF.1))+&($p_InLoadOrderModuleList_10).8)].1)), %var_7B0.4 ; 1800118C4 u=ds.2,sp+124.4,sp+308.1,(GLBLOW,sp+0..124,sp+128..308,sp+309..,SHADOW,ARGS,GLBHIGH) d=sp+128.4
283. 8 mov    #0x1E.4, %var_8A8.4     ; 1800118CB u=           d=sp+30.4
283. 9 goto   @3                      ; 1800118D3 u=
283. 9
284. 0 ; 1WAY-BLOCK 284 INBOUNDS: 4 OUTBOUNDS: 3 [START=1800118D8 END=1800119F2] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
284. 0 ; USE: sp+300.1
284. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,rcx.8,sp+30.4,sp+328.8
284. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
284. 0 xdu    (%var_5D8.1 & #0xF.1), rax.8 ; 180011978 u=sp+300.1   d=rax.8
284. 1 cfadd  rax.8, &($p_InLoadOrderModuleList_10).8, cf.1 ; 1800119DA u=rax.8      d=cf.1
284. 2 ofadd  rax.8, &($p_InLoadOrderModuleList_10).8, of.1 ; 1800119DA u=rax.8      d=of.1
284. 3 setz   (rax.8+&($p_InLoadOrderModuleList_10).8), #0.8, zf.1 ; 1800119DA u=rax.8      d=zf.1
284. 4 setp   (rax.8+&($p_InLoadOrderModuleList_10).8), #0.8, pf.1 ; 1800119DA u=rax.8      d=pf.1
284. 5 sets   (rax.8+&($p_InLoadOrderModuleList_10).8), sf.1 ; 1800119DA u=rax.8      d=sf.1
284. 6 add    rax.8, &($p_InLoadOrderModuleList_10).8, rcx.8 ; 1800119DA u=rax.8      d=rcx.8
284. 7 add    rax.8, &($p_InLoadOrderModuleList_10).8, %var_5B0.8 ; 1800119DD u=rax.8      d=sp+328.8
284. 8 mov    #0x1F.4, %var_8A8.4     ; 1800119E5 u=           d=sp+30.4
284. 9 goto   @3                      ; 1800119ED u=
284. 9
285. 0 ; 1WAY-BLOCK 285 INBOUNDS: 4 OUTBOUNDS: 286 [START=1800119F2 END=180011AAC] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
285. 0 ; USE: rsp.8,sp+49.1,(rbx.8,rbp.8,rdi.16,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..49,sp+4A..,SHADOW,ARGS,GLBHIGH)
285. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,sp+37.1,(r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm4.16,xmm5.16,GLBLOW,sp+0..37,sp+38..,RET,SHADOW,ARGS,GLBHIGH)
285. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1
285. 0 cfshl  (%var_88F.1 ^ #1.1), #2.1, cf.1 ; 180011A42 u=sp+49.1    d=cf.1
285. 1 xdu    (#4.1*(%var_88F.1 ^ #1.1)), rax.8 ; 180011A42 combined u=sp+49.1    d=rax.8
285. 2 und    of.1                    ; 180011A42 u=           d=of.1
285. 3 setz   (#4.1*(%var_88F.1 ^ #1.1)), #0.1, zf.1 ; 180011A42 u=sp+49.1    d=zf.1
285. 4 setp   (#4.1*(%var_88F.1 ^ #1.1)), #0.1, pf.1 ; 180011A42 u=sp+49.1    d=pf.1
285. 5 setnz  ((%var_88F.1 ^ #1.1) & #0x20.1), #0.1, sf.1 ; 180011A42 u=sp+49.1    d=sf.1
285. 6 mul    #4.1, (%var_88F.1 ^ #1.1), %var_8A1.1 ; 180011A8E u=sp+49.1    d=sp+37.1
285. 7 add    rsp.8, #0x37.8, r9.8    ; 180011A92 u=rsp.8      d=r9.8
285. 8 mov    #0x5E.8, rcx.8          ; 180011A97 u=           d=rcx.8
285. 9 mov    #0x36.8, rdx.8          ; 180011A9C u=           d=rdx.8
285.10 mov    #0x39.8, r8.8           ; 180011AA1 u=           d=r8.8
285.11 call   $sub_1801C72D0          ; 180011AA7 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm4.16,xmm5.16,ALLMEM)
285.11
286. 0 ; 1WAY-BLOCK 286 INBOUNDS: 285 OUTBOUNDS: 3 [START=180011AAC END=180011AC2] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
286. 0 ; USE: sp+37.1
286. 0 ; DEF: rax.8,sp+30.4,sp+4A.1
286. 0 ; DNU: rax.8
286. 0 xdu    %var_8A1.1, rax.8       ; 180011AAC u=sp+37.1    d=rax.8
286. 1 mov    %var_8A1.1, %var_88E.1  ; 180011AB1 u=sp+37.1    d=sp+4A.1
286. 2 mov    #4.4, %var_8A8.4        ; 180011AB5 u=           d=sp+30.4
286. 3 goto   @3                      ; 180011ABD u=
286. 3
287. 0 ; 1WAY-BLOCK 287 INBOUNDS: 4 OUTBOUNDS: 3 [START=180011AC2 END=180011B37] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
287. 0 ; DEF: cf.1,of.1,rax.8,sp+30.4,sp+F0.4,sp+104.4
287. 0 ; DNU: cf.1,of.1,rax^4.4
287. 0 mov    #0x6AC3DC33.4, %var_7E8.4 ; 180011B0E u=           d=sp+F0.4
287. 1 mov    call !__ROL4__<fast:_DWORD #0x6AC3DC33.4,char #2.1>.4, eax.4 ; 180011B20 u=           d=eax.4
287. 2 cfshl  #0x6AC3DC33.4, #2.1, cf.1 ; 180011B20 u=           d=cf.1
287. 3 und    of.1                    ; 180011B20 u=           d=of.1
287. 4 xdu    eax.4, rax.8            ; 180011B20 u=eax.4      d=rax^4.4
287. 5 mov    eax.4, %var_7D4.4       ; 180011B23 u=eax.4      d=sp+104.4
287. 6 mov    #0x13.4, %var_8A8.4     ; 180011B2A u=           d=sp+30.4
287. 7 goto   @3                      ; 180011B32 u=
287. 7
288. 0 ; 1WAY-BLOCK 288 INBOUNDS: 4 OUTBOUNDS: 289 [START=180011B37 END=180011B97] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
288. 0 ; USE: sp+D4.4,(rbx.8,rbp.8,rdi.16,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,sp+0..D4,sp+D8..,SHADOW,ARGS,GLBHIGH)
288. 0 ; DEF: rax.16,rcx.8,r8.8,sp+74.4,(cf.1,zf.1,sf.1,of.1,pf.1,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,GLBLOW,sp+0..74,sp+78..,RET,SHADOW,ARGS,GLBHIGH)
288. 0 xdu    %var_804.4, rax.8       ; 180011B37 u=sp+D4.4    d=rax.8
288. 1 mov    %var_804.4, %var_864.4  ; 180011B3E u=sp+D4.4    d=sp+74.4
288. 2 mov    #0x4E.8, rcx.8          ; 180011B82 u=           d=rcx.8
288. 3 mov    #0x2B.8, rdx.8          ; 180011B87 u=           d=rdx.8
288. 4 mov    #0x5C.8, r8.8           ; 180011B8C u=           d=r8.8
288. 5 call   $sub_180094930          ; 180011B92 u=(rax.16,rcx.16,rbp.8,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,r14.8,r15.8,st0.8,st1.8,st2.8,st3.8,st4.8,st5.8,st6.8,st7.8,mm0.8,mm1.8,mm2.8,mm3.8,mm4.8,mm5.8,mm6.8,mm7.8,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16,ymm0.32,ymm1.32,ymm2.32,ymm3.32,ymm4.32,ymm5.32,ymm6.32,ymm7.32,ymm8.32,ymm9.32,ymm10.32,ymm11.32,ymm12.32,ymm13.32,ymm14.32,ymm15.32,GLBLOW,LVARS,SHADOW,ARGS,GLBHIGH) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.8,r8.8,r9.8,r10.8,r11.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm4.16,xmm5.16,ALLMEM)
288. 5
289. 0 ; 2WAY-BLOCK 289 INBOUNDS: 288 OUTBOUNDS: 290 295 [START=180011B97 END=180011BAA] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
289. 0 ; USE: eax.4,sp+4D.1,sp+74.4
289. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8,sp+3F.1
289. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rcx.8
289. 0 xdu    %var_88B.1, rcx.8       ; 180011B97 u=sp+4D.1    d=rcx.8
289. 1 mov    %var_88B.1, %var_899.1  ; 180011B9C u=sp+4D.1    d=sp+3F.1
289. 2 setb   %var_864.4, eax.4, cf.1 ; 180011BA0 u=eax.4,sp+74.4 d=cf.1
289. 3 seto   %var_864.4, eax.4, of.1 ; 180011BA0 u=eax.4,sp+74.4 d=of.1
289. 4 setz   %var_864.4, eax.4, zf.1 ; 180011BA0 u=eax.4,sp+74.4 d=zf.1
289. 5 setp   %var_864.4, eax.4, pf.1 ; 180011BA0 u=eax.4,sp+74.4 d=pf.1
289. 6 sets   (%var_864.4-eax.4), sf.1 ; 180011BA0 u=eax.4,sp+74.4 d=sf.1
289. 7 jae    %var_864.4, eax.4, @295 ; 180011BA4 u=eax.4,sp+74.4
289. 7
290. 0 ; 1WAY-BLOCK 290 INBOUNDS: 289 OUTBOUNDS: 3 [START=180011BAA END=180011BB7] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
290. 0 ; DEF: sp+30.4
290. 0 mov    #0xC1.4, %var_8A8.4     ; 180011BAA u=           d=sp+30.4
290. 1 goto   @3                      ; 180011BB2 u=
290. 1
291. 0 ; 1WAY-BLOCK 291 INBOUNDS: 4 OUTBOUNDS: 3 [START=180011BB7 END=180011C98] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
291. 0 ; USE: sp+4A.1
291. 0 ; DEF: cf.1,zf.1,sf.1,of.1,pf.1,rax.8,sp+30.4,sp+3A.1,sp+4B.1
291. 0 ; DNU: cf.1,zf.1,sf.1,of.1,pf.1,rax^1.7
291. 0 add    %var_88E.1, #0x3A.1, %var_89E.1 ; 180011C1F u=sp+4A.1    d=sp+3A.1
291. 1 xdu    (%var_88E.1+#0x3A.1), rax.8 ; 180011C7F u=sp+4A.1    d=rax.8
291. 2 cfshr  al.1, #4.1, cf.1        ; 180011C84 u=al.1       d=cf.1
291. 3 shr    al.1, #4.1, al.1        ; 180011C84 u=al.1       d=al.1
291. 4 und    of.1                    ; 180011C84 u=           d=of.1
291. 5 setz   al.1, #0.1, zf.1        ; 180011C84 u=al.1       d=zf.1
291. 6 setp   al.1, #0.1, pf.1        ; 180011C84 u=al.1       d=pf.1
291. 7 mov    #0.1, sf.1              ; 180011C84 u=           d=sf.1
291. 8 mov    al.1, %var_88D.1        ; 180011C87 u=al.1       d=sp+4B.1
291. 9 mov    #5.4, %var_8A8.4        ; 180011C8B u=           d=sp+30.4
291.10 goto   @3                      ; 180011C93 u=
291.10
292. 0 ; 1WAY-BLOCK 292 INBOUNDS: 22 OUTBOUNDS: 3 [START=180011C98 END=180011CA5] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
292. 0 ; DEF: sp+30.4
292. 0 mov    #0x11.4, %var_8A8.4     ; 180011C98 u=           d=sp+30.4
292. 1 goto   @3                      ; 180011CA0 u=
292. 1
293. 0 ; 1WAY-BLOCK 293 INBOUNDS: 154 OUTBOUNDS: 3 [START=180011CA5 END=180011CB2] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
293. 0 ; DEF: sp+30.4
293. 0 mov    #0.1, al.1              ; 180011CA5 assert u=           d=al.1
293. 1 mov    #0xDA.4, %var_8A8.4     ; 180011CA5 u=           d=sp+30.4
293. 2 goto   @3                      ; 180011CAD u=
293. 2
294. 0 ; 1WAY-BLOCK 294 INBOUNDS: 175 OUTBOUNDS: 3 [START=180011CB2 END=180011CBF] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
294. 0 ; DEF: sp+30.4
294. 0 mov    #0.1, al.1              ; 180011CB2 assert u=           d=al.1
294. 1 mov    #0xDA.4, %var_8A8.4     ; 180011CB2 u=           d=sp+30.4
294. 2 goto   @3                      ; 180011CBA u=
294. 2
295. 0 ; 1WAY-BLOCK 295 INBOUNDS: 289 OUTBOUNDS: 3 [START=180011CBF END=180011CCC] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
295. 0 ; DEF: sp+30.4
295. 0 mov    #0xC.4, %var_8A8.4      ; 180011CBF u=           d=sp+30.4
295. 1 goto   @3                      ; 180011CC7 u=
295. 1
296. 0 ; 1WAY-BLOCK 296 INBOUNDS: 180 OUTBOUNDS: 3 [START=180011CCC END=180011CD9] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
296. 0 ; DEF: sp+30.4
296. 0 mov    #0.1, %var_89F.1        ; 180011CCC assert u=           d=sp+39.1
296. 1 mov    #0x12.4, %var_8A8.4     ; 180011CCC u=           d=sp+30.4
296. 2 goto   @3                      ; 180011CD4 u=
296. 2
297. 0 ; STOP-BLOCK 297 FAKE [START=FFFFFFFFFFFFFFFF END=FFFFFFFFFFFFFFFF] MINREFS: STK=0/ARG=8E0, MAXBSP: 0
297. 0 ; USE: (xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,xmm15.16)
297. 0
"""

import logging
import typing

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_nalt
import ida_pro
import idaapi
import idautils
import idc
import networkx as nx

# Attempt to import CFGRecovery from the sibling cfg_trace.py
# This might require IDA's Python environment to be configured correctly
# or for the scripts to be in a directory recognized as a package.
try:
    from .cfg_trace import CFGRecovery
except ImportError:
    # Fallback if relative import fails (e.g., script run in a way that doesn't define the package)
    # This assumes cfg_trace.py is in a path discoverable by Python's import system.
    # For a more robust solution, ensure your scripts directory is in PYTHONPATH
    # or handle this with a more explicit path manipulation if needed.
    try:
        import cfg_trace # type: ignore
        CFGRecovery = cfg_trace.CFGRecovery # type: ignore
    except ImportError:
        idaapi.msg("ERROR: CFGRecovery class from cfg_trace.py could not be imported.\n")
        idaapi.msg("Ensure cfg_trace.py is in the same directory or Python path.\n")
        CFGRecovery = None


class CFFUnflatten:
    """
    Orchestrates the unflattening of a control-flow flattened function
    using a recovered CFG.
    """

    def __init__(
        self,
        func_ea: int,
        cfg_graph: nx.DiGraph,
        dispatcher_var_idx: typing.Optional[int],
        case_block_info: dict,
    ):
        self.func_ea = func_ea
        self.func = idaapi.get_func(func_ea)
        self.cfg = cfg_graph
        self.dispatcher_var_idx = dispatcher_var_idx
        self.case_value_to_ea = {
            case_val: info["start_ea"] for case_val, info in case_block_info.items()
        }
        # Add obj_id to case_value_to_ea for easier lookup if needed
        self.case_value_to_obj_id = {
            case_val: info["case_item_obj_id"] for case_val, info in case_block_info.items()
        }

        self.logger = logging.getLogger(self.__class__.__name__)
        self.switch_instruction_ea: typing.Optional[int] = None
        self.cfunc: typing.Optional[ida_hexrays.cfuncptr_t] = None

    def _get_cfunc(self) -> typing.Optional[ida_hexrays.cfuncptr_t]:
        """Gets or refreshes the decompiled function."""
        if not self.cfunc:
            try:
                self.cfunc = idaapi.decompile(self.func_ea)
            except ida_hexrays.DecompilationFailure:
                self.logger.error("Failed to decompile function 0x%X", self.func_ea)
                return None
        return self.cfunc

    def map_switch_and_case_eas(self) -> bool:
        """
        Identifies the main switch instruction EA and verifies case EAs.
        The case_value_to_ea map is already populated from CFGRecovery's output.
        This function primarily finds the switch instruction EA.
        """
        cfunc = self._get_cfunc()
        if not cfunc:
            return False

        found_switch = False
        for item in cfunc.treeitems:  # item is a citem_t
            if item.op == idaapi.cit_switch:
                found_switch = True
                self.switch_instruction_ea = item.ea
                self.logger.info(
                    "Identified dispatcher switch instruction at EA 0x%X", item.ea
                )

                # Verify EAs from CFGRecovery against live cfunc if necessary (optional)
                # switch_insn: ida_hexrays.cswitch_t = item.cinsn.cswitch
                # for case_idx in range(switch_insn.cases.size()):
                #     case_item: ida_hexrays.ccase_t = switch_insn.cases.at(case_idx)
                #     for val_idx in range(case_item.values.size()):
                #         case_val = case_item.values.at(val_idx)
                #         if case_val in self.case_value_to_ea:
                #             if self.case_value_to_ea[case_val] != case_item.ea:
                #                 self.logger.warning(
                #                     "EA mismatch for case 0x%X: CFG_EA=0x%X, CFunc_EA=0x%X",
                #                     case_val, self.case_value_to_ea[case_val], case_item.ea
                #                 )
                #         else:
                #             self.logger.warning("Case 0x%X from cfunc not in CFG EAs.", case_val)
                break  # Assuming one main dispatcher switch

        if not found_switch:
            self.logger.error(
                "Could not find the main switch statement in function 0x%X.",
                self.func_ea,
            )
            return False
        return True

    def find_terminating_jmp_in_block(self, block_start_ea: int, case_val: int) -> typing.Optional[int]:
        """
        Finds the unconditional JMP instruction that likely terminates a case block
        and jumps back to the dispatcher loop.
        This JMP is the one we want to patch.

        Args:
            block_start_ea: The starting EA of the case block's code.
            case_val: The case value, for context in logging.

        Returns:
            The EA of the JMP instruction to patch, or None if not found.
        """
        cfunc = self._get_cfunc()
        if not cfunc or self.dispatcher_var_idx is None:
            return None

        # First, try to find the ccase_t item using its obj_id stored from CFGRecovery
        target_obj_id = self.case_value_to_obj_id.get(case_val)
        if target_obj_id is None:
            self.logger.warning("No obj_id found for case 0x%X. Cannot find citem directly.", case_val)
            return None

        case_citem = None
        # Search for the specific ccase_t using its obj_id
        # cfunc.treeitems provides all citem_t in the function.
        # We need to find the citem_t whose obj_id matches.
        # This is inefficient. A better way is to traverse from the switch.
        for item in cfunc.treeitems:
            if item.op == idaapi.cit_switch:
                switch_insn: ida_hexrays.cswitch_t = item.cinsn.cswitch
                for i in range(switch_insn.cases.size()):
                    cc = switch_insn.cases.at(i) # ccase_t
                    if cc.obj_id == target_obj_id:
                        case_citem = cc
                        break
                if case_citem:
                    break
        
        if not case_citem:
            self.logger.warning("Could not locate citem for case 0x%X (obj_id %s) in cfunc.", case_val, target_obj_id)
            # Fallback to basic block analysis if citem not found
            return self._find_jmp_by_bb_analysis(block_start_ea, case_val)


        # Traverse the statements within this case_citem (which is a cinsn_t, often a cblock)
        # Looking for a `goto` that leads back to the dispatcher, usually after dispatcher var assignment.
        # A ccase_t *is* a statement list. Iterate its contents if it's a block.
        
        # Simplified: Assume the last instruction in the basic block starting at block_start_ea
        # (or the block containing the dispatcher assignment) is the JMP.
        # The CFG trace already found dispatcher assignments.
        # The critical part is finding the JMP that *follows* such an assignment or terminates the semantic block.

        # Using a visitor to find the `goto` statement within the specific case block (citem)
        # This is complicated because the case_citem might not be simple.
        class GotoVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self, logger):
                super().__init__(ida_hexrays.CV_FAST)
                self.goto_eas = [] # Store EAs of cgoto_t items
                self.logger = logger
            
            def visit_insn(self, insn: ida_hexrays.cinsn_t):
                if insn.op == idaapi.cit_goto:
                    self.logger.debug("GotoVisitor: Found cit_goto at EA 0x%X", insn.ea)
                    self.goto_eas.append(insn.ea)
                return 0 # Continue traversal

        visitor = GotoVisitor(self.logger)
        # case_citem itself is a cinsn_t. If it's a block, apply_to its cblock.
        # However, apply_to expects a citem_t as the root for traversal.
        # A ccase_t is a citem_t, so we can apply to it directly.
        visitor.apply_to(case_citem, None)  # type: ignore


        if visitor.goto_eas:
            # Heuristic: the JMP to patch is likely the one with the highest address
            # within this case block, as it's typically the last action.
            # Or, it's the one immediately after the dispatcher var assignment.
            # This needs careful handling.
            # For now, if there are gotos, assume the one at highest EA is the candidate.
            # This also assumes the goto is an unconditional jump back to dispatcher head.
            candidate_jmp_ea = max(visitor.goto_eas) # JMPs are usually small, so EA itself is fine.
            self.logger.info(
                "Found candidate JMP (from cgoto_t) at 0x%X in case 0x%X (starts 0x%X)",
                candidate_jmp_ea, case_val, block_start_ea
            )
            return candidate_jmp_ea
        else:
            self.logger.debug("No explicit cgoto_t found in case 0x%X (0x%X). Trying BB analysis.", case_val, block_start_ea)
            return self._find_jmp_by_bb_analysis(block_start_ea, case_val)


    def _find_jmp_by_bb_analysis(self, block_start_ea: int, case_val: int) -> typing.Optional[int]:
        """Fallback to find JMP using basic block analysis."""
        func_graph = idaapi.FlowChart(idaapi.get_func(block_start_ea))
        for bb in func_graph:
            if bb.start_ea == block_start_ea: # Found the starting basic block for this case
                # Check the last instruction of this BB
                # A BB's end_ea points *after* the last instruction.
                # prev_head gives the start of the last instruction.
                last_insn_ea = idc.prev_head(bb.end_ea, bb.start_ea)
                if last_insn_ea != idaapi.BADADDR:
                    mnem = idc.print_insn_mnem(last_insn_ea)
                    if mnem == "jmp": # Unconditional jump
                        # Check if this jmp is to the dispatcher head (heuristic needed)
                        # For now, assume any JMP at end of case block is a candidate.
                        self.logger.info(
                            "Found candidate JMP (from BB analysis) at 0x%X in case 0x%X (BB 0x%X-0x%X)",
                            last_insn_ea, case_val, bb.start_ea, bb.end_ea
                        )
                        return last_insn_ea
                    elif mnem.startswith("ret"):
                         self.logger.info("Case 0x%X (0x%X) ends with RET at 0x%X. No JMP to patch for linking.", case_val, block_start_ea, last_insn_ea)
                         return None # This is a return block
                    else:
                        self.logger.warning("Case 0x%X (0x%X) BB 0x%X-0x%X ends with %s (0x%X), not JMP/RET.",
                                            case_val, block_start_ea, bb.start_ea, bb.end_ea, mnem, last_insn_ea)
                break # Processed the first BB starting at block_start_ea
        
        self.logger.warning("Could not find a clear terminating JMP for case 0x%X (starts 0x%X) via BB analysis.", case_val, block_start_ea)
        return None


    def patch_jump(self, from_ea: int, to_ea: int, comment: str = "") -> bool:
        """
        Patches the instruction at from_ea to be an unconditional near jump to to_ea.
        Attempts to NOP out remaining bytes of the original instruction if the new JMP is shorter.
        """
        self.logger.info("Patching 0x%X to JMP to 0x%X. (%s)", from_ea, to_ea, comment)
        from_ea = ida_bytes.get_item_head(from_ea)
        original_size = ida_bytes.get_item_size(from_ea)

        # JMP rel32: Opcode E9, followed by 4-byte relative offset
        # Offset = target_ea - (current_ea_of_jmp_operand + 4)
        # current_ea_of_jmp_operand = from_ea + 1 (byte for E9)
        # Total size of JMP rel32 is 5 bytes.
        # Relative offset = to_ea - (from_ea + 5)
        offset = to_ea - (from_ea + 5)

        # Check if offset fits in 32 bits (signed)
        if not (-(1 << 31) <= offset < (1 << 31)):
            self.logger.error(
                "Offset 0x%X is too large for JMP rel32 from 0x%X to 0x%X. Patching failed.",
                offset, from_ea, to_ea,
            )
            return False

        if original_size < 5:
            self.logger.error(
                "Original instruction at 0x%X (size %d) is too small to fit a 5-byte JMP rel32. Patching aborted.",
                from_ea, original_size
            )
            return False

        # Patch the JMP
        ida_bytes.patch_byte(from_ea, 0xE9)  # JMP opcode
        # IDA's patch_dword expects an unsigned value if it's for memory content
        ida_bytes.patch_dword(from_ea + 1, offset & 0xFFFFFFFF)

        # NOP out any remaining bytes of the original instruction
        bytes_to_nop = original_size - 5
        if bytes_to_nop > 0:
            for i in range(bytes_to_nop):
                ida_bytes.patch_byte(from_ea + 5 + i, 0x90)  # NOP
            self.logger.debug("NOPed %d bytes after JMP at 0x%X", bytes_to_nop, from_ea + 5)
        
        idc.set_cmt(from_ea, f"Unflattened: JMP to 0x{to_ea:X}. {comment}", False)
        return True

    def unflatten(self) -> bool:
        """Main unflattening logic."""
        self.logger.info("Starting CFF unflattening for function 0x%X", self.func_ea)
        if not self.func:
            self.logger.error("Function at 0x%X not found.", self.func_ea)
            return False

        if not self._get_cfunc() or not self.map_switch_and_case_eas():
            self.logger.error("Initial analysis (decompile, switch find) failed. Aborting.")
            return False

        if not self.cfg.nodes:
            self.logger.error("CFG is empty. Aborting.")
            return False

        # 1. Determine the actual entry point of the unflattened function
        start_nodes = [node for node, degree in self.cfg.in_degree() if degree == 0]
        if not start_nodes:
            # Fallback: If CFG has a 'start_node' attribute from CFGRecovery (not standard, but could be added)
            # Or, try the node with the smallest case value if all are integers.
            if self.cfg.nodes:
                 # Heuristic: try smallest numeric case value or first node.
                potential_starts = sorted([n for n in self.cfg.nodes() if isinstance(n, int)], reverse=False)
                if potential_starts:
                    start_nodes = [potential_starts[0]]
                    self.logger.warning("No node with in-degree 0. Using smallest case value 0x%X as entry.", start_nodes[0])
                else: # No numeric nodes or no nodes
                     self.logger.error("No node with in-degree 0 and no suitable fallback start node in CFG. Aborting.")
                     return False
            else: # Should have been caught by self.cfg.nodes check earlier
                self.logger.error("CFG has no nodes. Cannot determine start node.")
                return False


        if len(start_nodes) > 1:
            self.logger.warning(
                "Multiple CFG start nodes found: %s. Using the first: 0x%X",
                [hex(n) if isinstance(n, int) else str(n) for n in start_nodes],
                start_nodes[0],
            )
        unflattened_entry_case_val = start_nodes[0]
        unflattened_entry_ea = self.case_value_to_ea.get(unflattened_entry_case_val)

        if unflattened_entry_ea is None:
            self.logger.error(
                "Could not find EA for unflattened entry case value 0x%X. Aborting.",
                unflattened_entry_case_val,
            )
            return False
        self.logger.info(
            "Determined unflattened entry point: case 0x%X at EA 0x%X",
            unflattened_entry_case_val,
            unflattened_entry_ea,
        )

        # 2. Patch the function's original entry to jump to this unflattened_entry_ea
        function_start_ea = self.func.start_ea
        self.logger.info(
            "Patching function entry 0x%X to JMP to unflattened CFG entry 0x%X",
            function_start_ea,
            unflattened_entry_ea,
        )
        if not self.patch_jump(function_start_ea, unflattened_entry_ea, "Patched func entry to CFG start"):
            self.logger.error("Failed to patch function entry. Aborting.")
            return False

        # 3. For each block in the CFG, patch its exit JMP
        for case_val_src in self.cfg.nodes:
            block_start_ea = self.case_value_to_ea.get(case_val_src)
            if block_start_ea is None:
                self.logger.warning(
                    "Skipping case 0x%X: EA not found in case_value_to_ea map.",
                    case_val_src,
                )
                continue

            self.logger.debug(
                "Processing block for case 0x%X (starts at 0x%X)",
                case_val_src,
                block_start_ea,
            )

            successors = list(self.cfg.successors(case_val_src))
            if len(successors) == 1:  # Unconditional jump in CFG
                jmp_to_patch_ea = self.find_terminating_jmp_in_block(block_start_ea, case_val_src)
                if jmp_to_patch_ea is None:
                    self.logger.warning(
                        "No JMP found to patch for case 0x%X (0x%X) which has one successor. Block might end differently (e.g. RET already, or analysis failed).",
                        case_val_src,
                        block_start_ea,
                    )
                    continue

                case_val_dst = successors[0]
                target_ea = self.case_value_to_ea.get(case_val_dst)
                if target_ea is None:
                    self.logger.error(
                        "EA for successor case 0x%X not found. Cannot patch JMP from 0x%X (case 0x%X)",
                        case_val_dst,
                        block_start_ea,
                        case_val_src,
                    )
                    continue
                
                patch_comment = f"Case 0x{case_val_src:X} -> 0x{case_val_dst:X}"
                if not self.patch_jump(jmp_to_patch_ea, target_ea, patch_comment):
                    self.logger.error(
                        "Failed to patch JMP at 0x%X (for case 0x%X) to 0x%X (case 0x%X)",
                        jmp_to_patch_ea, case_val_src, target_ea, case_val_dst
                    )

            elif len(successors) > 1:
                # Conditional branches. This script currently assumes cfg_trace provides unconditional links.
                # If cfg_trace were to provide conditions, re-writing them is much more complex.
                self.logger.warning(
                    "Case 0x%X (0x%X) has %d successors in CFG: %s. Re-writing conditional branches is not yet supported. This block will not be patched.",
                    case_val_src,
                    block_start_ea,
                    len(successors),
                    [hex(s) if isinstance(s, int) else str(s) for s in successors],
                )
            elif len(successors) == 0:
                # This block should end with a RET or be an exit block.
                # Verify find_terminating_jmp_in_block behavior for RET blocks.
                # If it correctly returns None for RETs, this is fine.
                self.logger.info(
                    "Case 0x%X (0x%X) is a terminal node in CFG. Expecting it to RET.",
                    case_val_src,
                    block_start_ea,
                )
                # Optionally, verify it does end in RET here.
                # self.find_terminating_jmp_in_block should have logged if it's a RET.


        # 4. NOP out the original dispatcher switch table jump
        if self.switch_instruction_ea:
            switch_jmp_size = ida_bytes.get_item_size(self.switch_instruction_ea)
            self.logger.info(
                "NOPing out original dispatcher switch JMP at 0x%X (size %d bytes)",
                self.switch_instruction_ea,
                switch_jmp_size,
            )
            for i in range(switch_jmp_size):
                ida_bytes.patch_byte(self.switch_instruction_ea + i, 0x90)  # NOP
            idc.set_cmt(self.switch_instruction_ea, "Unflattened: Original dispatcher NOPed", False)
        else:
            self.logger.warning("Switch instruction EA not found, cannot NOP it out.")

        self.logger.info(
            "Unflattening patches applied for 0x%X. Requesting IDA reanalysis.",
            self.func_ea,
        )
        
        # Request IDA to reanalyze the function
        # A more robust way than del_func then plan_ea:
        ida_funcs.remove_func_tail(self.func, self.func_ea) # Remove existing flow chart info
        ida_auto.plan_ea(self.func.start_ea) # Plan for reanalysis starting from function entry

        # Force reanalysis of the function boundaries
        ida_auto.auto_wait() # Allow IDA to process pending actions

        # Refresh Hex-Rays views if open
        vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_widget())
        if vu and vu.cfunc and vu.cfunc.entry_ea == self.func_ea:
            vu.refresh_view(True)
        
        self.logger.info("IDA reanalysis requested. Decompilation may need to be manually refreshed.")
        return True


def main_unflatten_ida_entry():
    """Entry point when script is run from IDA."""
    logging.basicConfig(
        level=logging.INFO, # Adjust to DEBUG for more verbose output
        format="%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger = logging.getLogger(__name__ + ".main_unflatten_ida_entry")

    if CFGRecovery is None:
        logger.error("CFGRecovery class is not available. Cannot proceed.")
        return

    func_ea = idc.get_screen_ea()
    if func_ea == idaapi.BADADDR or not idaapi.get_func(func_ea):
        current_func_name = idc.get_func_name(func_ea) if func_ea != idaapi.BADADDR else "BADADDR"
        logger.error(
            "Please position the cursor within a valid target function. Current EA: 0x%X (%s)",
             func_ea, current_func_name
        )
        idaapi.warning("CFF Unflatten: No function at current address or invalid address.")
        return

    logger.info("Starting CFF Unflattening process for function at 0x%X (%s)", func_ea, idc.get_func_name(func_ea))

    # 1. Recover CFG using CFGRecovery
    cfg_tool = CFGRecovery(func_ea)
    if not cfg_tool.run():  # run() populates graph, dispatcher_var, blocks
        logger.error("CFG Recovery phase failed for function 0x%X.", func_ea)
        idaapi.warning(f"CFF Unflatten: CFG Recovery failed for 0x{func_ea:X}.")
        return

    if cfg_tool.dispatcher_var is None:
        logger.error(
            "CFG Recovery did not identify a dispatcher variable for function 0x%X.", func_ea
        )
        idaapi.warning(f"CFF Unflatten: Could not find dispatcher variable for 0x{func_ea:X}.")
        return

    if not cfg_tool.graph or not cfg_tool.blocks:
        logger.error("CFG Recovery resulted in an empty graph or no blocks for 0x%X.", func_ea)
        idaapi.warning(f"CFF Unflatten: CFG Recovery gave empty graph/blocks for 0x{func_ea:X}.")
        return
    
    logger.info("CFG Recovery successful. Dispatcher var_idx: %s. Found %d nodes, %d edges. %d blocks.",
                cfg_tool.dispatcher_var, len(cfg_tool.graph.nodes), len(cfg_tool.graph.edges), len(cfg_tool.blocks))


    # 2. Initialize and run the unflattening process
    unflattener = CFFUnflatten(
        func_ea, cfg_tool.graph, cfg_tool.dispatcher_var, cfg_tool.blocks
    )
    
    if unflattener.unflatten():
        logger.info("CFF Unflattening process completed for 0x%X.", func_ea)
        idaapi.msg(f"CFF Unflattening for 0x{func_ea:X} done. Please check results and re-decompile if necessary.
")
    else:
        logger.error("CFF Unflattening process failed for 0x%X.", func_ea)
        idaapi.warning(f"CFF Unflattening for 0x{func_ea:X} failed. Check logs for details.
")


if __name__ == "__main__":
    # This allows the script to be run from IDA's script execution dialog
    # Ensure logging is set up if you run this block directly for testing outside IDA
    # (though it's designed for IDA's environment).
    main_unflatten_ida_entry()
