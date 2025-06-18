__int64 sub_18011CFF0()
{
    // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

LABEL_x1D055:
    p_InLoadOrderModuleList = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    p_InLoadOrderModuleList_1 = p_InLoadOrderModuleList->Flink;

LABEL_x21718:
    Flink_1 = p_InLoadOrderModuleList_1;
    v144 = 0;
    if ( p_InLoadOrderModuleList_1 != p_InLoadOrderModuleList )
    {
        while ( 1 )
        {
LABEL_x25592:
            Flink = Flink_1;
            sub_18015EE30(i_1, 0x4B, 0x45, 6);
            v71 = LOWORD(Flink_1[5].Blink) >> 1;

LABEL_x2537B:
            sub_1800967D0(0x20, (unsigned int)i_1, (unsigned int)&v439, Flink[6].Flink, 0xA, v71);
            v26 = i_1[0];
            for ( i = i_1; v26; i = i_2 + 1 )
            {
LABEL_x2522E:
                i_2 = i;
                v13 = v26 + 0x20;
                if ( (unsigned int)(v26 - 0x41) >= 0x1A )
                    v13 = v26;

                v27 = v13;

LABEL_x1E6E7:
                *i_2 = v27;
                v26 = i_2[1];
            }

LABEL_x1D00A:
            i_3 = i_1;
            v307 = 0xCBF29CE484222325uLL;
            do
            {
LABEL_x1FEAC:
                v334 = v307;
                i_4 = i_3 + 1;
                v28 = *i_3;
                v29 = *i_3 == 0;

LABEL_x1D290:
                i_3 = i_4;
                v307 = 0x100000001B3LL * (v334 ^ v28);
                v424 = v334;
            }
            while ( !v29 );

LABEL_x25737:
            v434 = Flink;
            if ( v424 == 0xE14B18A7ACF9C443uLL )
                break;

LABEL_x1F19D:
            Flink_1 = Flink->Flink;
            v144 = 0;
            if ( Flink_1 == p_InLoadOrderModuleList )
                goto LABEL_x1E726;
        }

LABEL_x21456:
        v144 = (unsigned __int16 *)v434[3].Flink;
    }

LABEL_x1E726:
    v104 = v144;

LABEL_x23B5C:
    n0x5A4D = *v144;
    v67 = 0;
    v68 = 0;
    v69 = 0;
    v70 = 0;
    if ( n0x5A4D != 0x5A4D )
        goto LABEL_x2585D;

LABEL_x1FC5C:
    v133 = (_DWORD *)((char *)v104 + *((int *)v144 + 0xF));
    v16 = *v133 == 0x4550;
    v67 = 0;
    v68 = 0;
    v69 = 0;
    v70 = 0;
    if ( v16 )
    {
LABEL_x23069:
        v125 = v133[0x22];
        v145 = 0;
        if ( !v125 )
            goto LABEL_x22AAA;

LABEL_x22F2F:
        v291 = (_DWORD *)((char *)v144 + v125);
        v395 = (char *)v144 + (unsigned int)v291[8];
        v396 = v291 + 7;

LABEL_x1FA12:
        v397 = (char *)v144 + *v396;
        v398 = (char *)v144 + (unsigned int)v291[9];

LABEL_x23474:
        v271 = v291[6];
        v145 = 0;
        if ( !v271 )
            goto LABEL_x22AAA;

LABEL_x238D6:
        v399 = v271;
        v314 = 0;

LABEL_x1EF53:
        while ( 1 )
        {
            v292 = v314;
            v293 = (char *)v104 + *(unsigned int *)&v397[4 * *(unsigned __int16 *)&v398[2 * v314]];

LABEL_x20B9E:
            if ( v293 )
                break;

LABEL_x203F0:
            v314 = v292 + 1;
            v317 = 0;
            if ( v292 + 1 == v399 )
                goto LABEL_x1F37B;
        }

LABEL_x204E9:
        v315 = (char *)v144 + *(unsigned int *)&v395[4 * v292];
        v316 = 0xCBF29CE484222325uLL;

LABEL_x2353D:
        for ( j = 0xE0; ; j = 0xD )
        {
            while ( 2 )
            {
                switch ( j )
                {
                    case 0:
                        goto LABEL_x1D055;

                    case 1:
                        goto LABEL_x21718;

                    case 2:
                        goto LABEL_x25592;

                    case 3:
                        goto LABEL_x2537B;

                    case 4:
                        goto LABEL_x2522E;

                    case 5:
                        goto LABEL_x1E6E7;

                    case 6:
                        goto LABEL_x1D00A;

                    case 7:
                        goto LABEL_x1FEAC;

                    case 8:
                        goto LABEL_x1D290;

                    case 9:
                        goto LABEL_x25737;

                    case 0xA:
                        goto LABEL_x1F19D;

                    case 0xB:
                        goto LABEL_x1E726;

                    case 0xC:
                        goto LABEL_x23B5C;

                    case 0xD:
                        goto LABEL_x2585D;

                    case 0xE:
                        goto LABEL_x1DFFC;

                    case 0xF:
                        goto LABEL_x23BAC;

                    case 0x10:
                        goto LABEL_x2504F;

                    case 0x11:
                        goto LABEL_x255E3;

                    case 0x12:
                    case 0x13:
                        goto LABEL_x1DF35;

                    case 0x14:
                        goto LABEL_x251AE;

                    case 0x15:
                        goto LABEL_x25532;

                    case 0x16:
                        goto LABEL_x243B4;

                    case 0x17:
                        goto LABEL_x2319C;

                    case 0x18:
                        goto LABEL_x2576C;

                    case 0x19:
                        goto LABEL_x1D6C1;

                    case 0x1A:
                        goto LABEL_x256CB;

                    case 0x1B:
                        goto LABEL_x232D1;

                    case 0x1C:
                        goto LABEL_x24B42;

                    case 0x1D:
                        goto LABEL_x1D2E6;

                    case 0x1E:
                        goto LABEL_x20811;

                    case 0x1F:
                        goto LABEL_x22299;

                    case 0x20:
                        goto LABEL_x1D255;

                    case 0x21:
                        goto LABEL_x1D630;

                    case 0x22:
                        goto LABEL_x24DC8;

                    case 0x23:
                        goto LABEL_x25437;

                    case 0x24:
                        goto LABEL_x23117;

                    case 0x25:
                        goto LABEL_x1D0D8;

                    case 0x26:
                        goto LABEL_x24377;

                    case 0x27:
                        goto LABEL_x24348;

                    case 0x28:
                        goto LABEL_x20781;

                    case 0x29:
                        goto LABEL_x2322D;

                    case 0x2A:
                        goto LABEL_x22E41;

                    case 0x2B:
                        goto LABEL_x1D08E;

                    case 0x2C:
                        goto LABEL_x2468E;

                    case 0x2D:
                        goto LABEL_x1FFCA;

                    case 0x2E:
                        goto LABEL_x1D1BC;

                    case 0x2F:
                        goto LABEL_x23FBF;

                    case 0x30:
                        goto LABEL_x1D452;

                    case 0x31:
                        goto LABEL_x251F5;

                    case 0x32:
                        goto LABEL_x2554F;

                    case 0x33:
                        goto LABEL_x247DD;

                    case 0x34:
                        goto LABEL_x24739;

                    case 0x35:
                        goto LABEL_x20681;

                    case 0x36:
                        goto LABEL_x236C9;

                    case 0x37:
                        goto LABEL_x250C0;

                    case 0x38:
                        goto LABEL_x1D42A;

                    case 0x39:
                        goto LABEL_x1F17B;

                    case 0x3A:
                        goto LABEL_x2426B;

                    case 0x3B:
                        goto LABEL_x1D9FB;

                    case 0x3C:
                        goto LABEL_x1EFE6;

                    case 0x3D:
                        goto LABEL_x21F5E;

                    case 0x3E:
                        goto LABEL_x1D77F;

                    case 0x3F:
                        goto LABEL_x1D498;

                    case 0x40:
                        goto LABEL_x1D5E5;

                    case 0x41:
                        goto LABEL_x1D96A;

                    case 0x42:
                        goto LABEL_x1EBBC;

                    case 0x43:
                        goto LABEL_x2499F;

                    case 0x44:
                        goto LABEL_x252A7;

                    case 0x45:
                        goto LABEL_x1D8FB;

                    case 0x46:
                        goto LABEL_x1F039;

                    case 0x47:
                        goto LABEL_x1D500;

                    case 0x48:
                        goto LABEL_x23737;

                    case 0x49:
                        goto LABEL_x248BE;

                    case 0x4A:
                        goto LABEL_x1D153;

                    case 0x4B:
                        goto LABEL_x24806;

                    case 0x4C:
                        goto LABEL_x23E7B;

                    case 0x4D:
                        goto LABEL_x2203F;

                    case 0x4E:
                        goto LABEL_x1EABF;

                    case 0x4F:
                        goto LABEL_x1E67D;

                    case 0x50:
                        goto LABEL_x24904;

                    case 0x51:
                        goto LABEL_x1F5A0;

                    case 0x52:
                        goto LABEL_x24E27;

                    case 0x53:
                        goto LABEL_x1DAB3;

                    case 0x54:
                        goto LABEL_x2354A;

                    case 0x55:
                        goto LABEL_x20FBA;

                    case 0x56:
                        goto LABEL_x21547;

                    case 0x57:
                        goto LABEL_x21D78;

                    case 0x58:
                        goto LABEL_x239EA;

                    case 0x59:
                        goto LABEL_x1DF6A;

                    case 0x5A:
                        goto LABEL_x25019;

                    case 0x5B:
                        goto LABEL_x21E07;

                    case 0x5C:
                        goto LABEL_x1DE02;

                    case 0x5D:
                        goto LABEL_x1F344;

                    case 0x5E:
                        goto LABEL_x241BF;

                    case 0x5F:
                        goto LABEL_x1D935;

                    case 0x60:
                        goto LABEL_x1D384;

                    case 0x61:
                        goto LABEL_x24CB7;

                    case 0x62:
                        goto LABEL_x23160;

                    case 0x63:
                        goto LABEL_x1F5E3;

                    case 0x64:
                        goto LABEL_x246BF;

                    case 0x65:
                        goto LABEL_x23EC5;

                    case 0x66:
                        goto LABEL_x1EDCD;

                    case 0x67:
                        goto LABEL_x1E9C9;

                    case 0x68:
                        goto LABEL_x23023;

                    case 0x69:
                        goto LABEL_x22941;

                    case 0x6A:
                        goto LABEL_x24C41;

                    case 0x6B:
                        goto LABEL_x24A14;

                    case 0x6C:
                        goto LABEL_x1D30C;

                    case 0x6D:
                        goto LABEL_x1ED3A;

                    case 0x6E:
                        goto LABEL_x1E79C;

                    case 0x6F:
                        goto LABEL_x24835;

                    case 0x70:
                        goto LABEL_x1F3CF;

                    case 0x71:
                        goto LABEL_x24466;

                    case 0x72:
                        goto LABEL_x2059F;

                    case 0x73:
                    case 0x74:
                    case 0xD5:
                        goto LABEL_x24B02;

                    case 0x75:
                        goto LABEL_x1DB7B;

                    case 0x76:
                        goto LABEL_x23C68;

                    case 0x77:
                        goto LABEL_x23CAB;

                    case 0x78:
                        goto LABEL_x24DF5;

                    case 0x79:
                        goto LABEL_x24EE1;

                    case 0x7A:
                        goto LABEL_x24537;

                    case 0x7B:
                        goto LABEL_x1E3F2;

                    case 0x7C:
                        goto LABEL_x23E4D;

                    case 0x7D:
                        goto LABEL_x2088E;

                    case 0x7E:
                        return ((__int64 (__fastcall *)(__int64))(&byte_18027B8E0 + 0x7A))(v130);

                    case 0x7F:
                        goto LABEL_x220A1;

                    case 0x80:
                        goto LABEL_x1F670;

                    case 0x81:
                        goto LABEL_x2361F;

                    case 0x82:
                        goto LABEL_x2413E;

                    case 0x83:
                        goto LABEL_x24BCF;

                    case 0x84:
                        goto LABEL_x1FE27;

                    case 0x85:
                        goto LABEL_x1DEF9;

                    case 0x86:
                        goto LABEL_x1E2EE;

                    case 0x87:
                        goto LABEL_x22FB2;

                    case 0x88:
                        goto LABEL_x201CC;

                    case 0x89:
                        goto LABEL_x2405C;

                    case 0x8A:
                        goto LABEL_x24568;

                    case 0x8B:
                        goto LABEL_x1D87A;

                    case 0x8C:
                        goto LABEL_x1D4D8;

                    case 0x8D:
                        goto LABEL_x20208;

                    case 0x8E:
                        goto LABEL_x208C8;

                    case 0x8F:
                        goto LABEL_x2225A;

                    case 0x90:
                        goto LABEL_x20C37;

                    case 0x91:
                        goto LABEL_x22107;

                    case 0x92:
                        goto LABEL_x210D7;

                    case 0x93:
                        goto LABEL_x233E3;

                    case 0x94:
                        goto LABEL_x1D659;

                    case 0x95:
                        goto LABEL_x1E097;

                    case 0x96:
                        goto LABEL_x20A4C;

                    case 0x97:
                        goto LABEL_x1E8EF;

                    case 0x98:
                        goto LABEL_x225E8;

                    case 0x99:
                        goto LABEL_x227F5;

                    case 0x9A:
                        goto LABEL_x20520;

                    case 0x9B:
                        goto LABEL_x22D81;

                    case 0x9C:
                        goto LABEL_x2253C;

                    case 0x9D:
                        goto LABEL_x1F502;

                    case 0x9E:
                        goto LABEL_x1F6CB;

                    case 0x9F:
                        goto LABEL_x22708;

                    case 0xA0:
                        goto LABEL_x22F72;

                    case 0xA1:
                        goto LABEL_x1DC85;

                    case 0xA2:
                        goto LABEL_x1E1B0;

                    case 0xA3:
                        goto LABEL_x1F69D;

                    case 0xA4:
                        goto LABEL_x1FAA5;

                    case 0xA5:
                        goto LABEL_x1E5F9;

                    case 0xA6:
                        goto LABEL_x1E9FC;

                    case 0xA7:
                        goto LABEL_x23841;

                    case 0xA8:
                        goto LABEL_x238FE;

                    case 0xA9:
                        goto LABEL_x1F453;

                    case 0xAA:
                        goto LABEL_x23AB3;

                    case 0xAB:
                        goto LABEL_x23F8E;

                    case 0xAC:
                        goto LABEL_x245F2;

                    case 0xAD:
                        goto LABEL_x2157B;

                    case 0xAE:
                        goto LABEL_x243EB;

                    case 0xAF:
                        goto LABEL_x1E91D;

                    case 0xB0:
                        goto LABEL_x23E19;

                    case 0xB1:
                        goto LABEL_x2174F;

                    case 0xB2:
                        goto LABEL_x1EE5B;

                    case 0xB3:
                        goto LABEL_x2151A;

                    case 0xB4:
                        goto LABEL_x1E53E;

                    case 0xB5:
                        goto LABEL_x24099;

                    case 0xB6:
                        goto LABEL_x240CA;

                    case 0xB7:
                        goto LABEL_x1F28C;

                    case 0xB8:
                        goto LABEL_x23773;

                    case 0xB9:
                        goto LABEL_x22451;

                    case 0xBA:
                        goto LABEL_x22375;

                    case 0xBB:
                        goto LABEL_x1E125;

                    case 0xBC:
                        goto LABEL_x1E4AF;

                    case 0xBD:
                        goto LABEL_x208F3;

                    case 0xBE:
                        goto LABEL_x20AD9;

                    case 0xBF:
                        goto LABEL_x1F7D3;

                    case 0xC0:
                        goto LABEL_x1E80B;

                    case 0xC1:
                        goto LABEL_x239AE;

                    case 0xC2:
                        goto LABEL_x1ECC2;

                    case 0xC3:
                        goto LABEL_x21872;

                    case 0xC4:
                        goto LABEL_x1FCC8;

                    case 0xC5:
                        goto LABEL_x237A8;

                    case 0xC6:
                        goto LABEL_x235EA;

                    case 0xC7:
                        goto LABEL_x22FF2;

                    case 0xC8:
                        goto LABEL_x1F881;

                    case 0xC9:
                        goto LABEL_x1EA98;

                    case 0xCA:
                        goto LABEL_x1FFF9;

                    case 0xCB:
                        goto LABEL_x23D8A;

                    case 0xCC:
                        goto LABEL_x203C7;

                    case 0xCD:
                        goto LABEL_x1F745;

                    case 0xCE:
                        goto LABEL_x219E3;

                    case 0xCF:
                        goto LABEL_x20DDA;

                    case 0xD0:
                        goto LABEL_x21217;

                    case 0xD1:
                        goto LABEL_x21A19;

                    case 0xD2:
                        goto LABEL_x218F6;

                    case 0xD3:
                        goto LABEL_x20CD7;

                    case 0xD4:
                        goto LABEL_x22B5D;

                    case 0xD6:
                        goto LABEL_x22A38;

                    case 0xD7:
                        goto LABEL_x1FC5C;

                    case 0xD8:
                        goto LABEL_x23069;

                    case 0xD9:
                        goto LABEL_x22F2F;

                    case 0xDA:
                        goto LABEL_x1FA12;

                    case 0xDB:
                        goto LABEL_x23474;

                    case 0xDC:
                        goto LABEL_x238D6;

                    case 0xDD:
                        goto LABEL_x1EF53;

                    case 0xDE:
                        goto LABEL_x20B9E;

                    case 0xDF:
                        goto LABEL_x204E9;

                    case 0xE0:
                        v294 = v316;
                        v400 = v315 + 1;
                        v53 = *v315 == 0;
                        v401 = (unsigned __int8)*v315;
                        goto LABEL_x234A7;

                    case 0xE1:
LABEL_x234A7:
                        v315 = v400;
                        v316 = 0x100000001B3LL * (v401 ^ v294);
                        v426 = v294;
                        if ( !v53 )
                            goto LABEL_x2353D;

                        goto LABEL_x2206C;

                    case 0xE2:
LABEL_x2206C:
                        v433 = v293;
                        if ( v426 == 0x1A5EDE5545AE453BLL )
                            goto LABEL_x21439;

                        goto LABEL_x203F0;

                    case 0xE3:
                        goto LABEL_x203F0;

                    case 0xE4:
                        break;

                    case 0xE5:
                        goto LABEL_x22AAA;

                    case 0xE6:
                        goto LABEL_x21786;

                    case 0xE7:
                        goto LABEL_x20C07;

                    case 0xE8:
                        goto LABEL_x228AD;

                    case 0xE9:
                        goto LABEL_x22E19;

                    case 0xEA:
                        goto LABEL_x1F963;

                    case 0xEB:
                        goto LABEL_x1FE0B;

                    case 0xEC:
                        goto LABEL_x1FCF6;

                    case 0xED:
                        goto LABEL_x20185;

                    case 0xEE:
                        goto LABEL_x20496;

                    case 0xEF:
                        goto LABEL_x21F29;

                    case 0xF0:
                        goto LABEL_x21662;

                    case 0xF1:
                        goto LABEL_x21EC9;

                    case 0xF2:
                        goto LABEL_x22C99;

                    case 0xF3:
                        goto LABEL_x22C56;

                    case 0xF4:
                        goto LABEL_x200E0;

                    case 0xF5:
                        goto LABEL_x22E6F;

                    case 0xF6:
                        goto LABEL_x20EDE;

                    case 0xF7:
                        goto LABEL_x20F06;

                    case 0xF8:
                        goto LABEL_x22C3A;

                    case 0xF9:
                        goto LABEL_x22412;

                    case 0xFA:
                        goto LABEL_x21AAE;

                    case 0xFB:
                        goto LABEL_x218A3;

                    case 0xFC:
                        goto LABEL_x229B9;

                    case 0xFD:
                        goto LABEL_x21BA2;

                    case 0xFE:
                        goto LABEL_x216AC;

                    case 0xFF:
                        goto LABEL_x202DC;

                    case 0x100:
                        goto LABEL_x21044;

                    case 0x101:
                        goto LABEL_x2042A;

                    case 0x102:
                        goto LABEL_x21AF5;

                    case 0x103:
                        goto LABEL_x20E77;

                    case 0x104:
                        goto LABEL_x209BE;

                    case 0x105:
                        goto LABEL_x21BFC;

                    case 0x106:
                        goto LABEL_x20E9F;

                    case 0x107:
                        goto LABEL_x21C75;

                    case 0x108:
                        goto LABEL_x21366;

                    case 0x109:
                        goto LABEL_x21B6D;

                    case 0x10A:
                        goto LABEL_x2193B;

                    case 0x10B:
                        goto LABEL_x20BBA;

                    case 0x10C:
                        goto LABEL_x21329;

                    case 0x10D:
                        goto LABEL_x20F8D;

                    case 0x10E:
LABEL_x21439:
                        v317 = (void (__fastcall *)(_QWORD, _QWORD, _QWORD))v433;
                        break;

                    case 0x10F:
                        goto LABEL_x21456;

                    default:
                        continue;
                }

                break;
            }

LABEL_x1F37B:
            v67 = 0;
            v68 = (void (__fastcall *)(_QWORD, __int64 (__fastcall *)(), __int64 *))v317;
            v69 = 0;
            v70 = 0;
            v145 = v317;
            if ( !v16 )
                break;

LABEL_x22AAA:
            v134 = v145;
            v9 = v133[0x22];
            v147 = v145;
            v272 = v9;
            v146 = 0;
            if ( !v9 )
                goto LABEL_x22C99;

LABEL_x21786:
            v295 = (_DWORD *)((char *)v144 + v272);
            v402 = (char *)v144 + (unsigned int)v295[8];

LABEL_x20C07:
            v403 = (char *)v144 + (unsigned int)v295[7];
            v404 = (unsigned int)v295[9];

LABEL_x228AD:
            v405 = (char *)v144 + v404;
            v8 = v295[6];
            v147 = v134;
            v273 = v8;
            v146 = 0;
            if ( v8 )
            {
LABEL_x22E19:
                v406 = v273;
                v318 = 0;
                while ( 1 )
                {
LABEL_x1F963:
                    v296 = v318;
                    v297 = (char *)v104
                         + *(unsigned int *)&v403[4 * *(unsigned __int16 *)&v405[2 * v318]];

LABEL_x1FE0B:
                    if ( v297 )
                    {
LABEL_x1FCF6:
                        v319 = (unsigned __int8 *)v144 + *(unsigned int *)&v402[4 * v296];
                        v320 = 0xCBF29CE484222325uLL;
                        do
                        {
LABEL_x20185:
                            v407 = v320;
                            v408 = v319 + 1;
                            v3 = *v319;
                            v54 = v3 == 0;
                            v409 = v3 ^ v320;

LABEL_x20496:
                            v319 = v408;
                            v320 = 0x100000001B3LL * v409;
                            v427 = v407;
                        }
                        while ( !v54 );

LABEL_x21F29:
                        v432 = v297;
                        if ( v427 == 0x578960F1FC7FFF25LL )
                        {
LABEL_x20F8D:
                            v321 = v134;
                            v322 = (__int64 (__fastcall *)(_QWORD, _QWORD))v432;

LABEL_x21EC9:
                            v67 = 0;
                            v68 = (void (__fastcall *)(_QWORD, __int64 (__fastcall *)(), __int64 *))v321;
                            v69 = (__int64 (__fastcall *)(__int64, __int64 *))v322;
                            v70 = 0;
                            v146 = v322;
                            v147 = v321;
                            if ( !v16 )
                                goto LABEL_x2585D;

                            break;
                        }
                    }

LABEL_x21662:
                    v318 = v296 + 1;
                    v321 = v134;
                    v322 = 0;
                    if ( v296 + 1 == v406 )
                        goto LABEL_x21EC9;
                }
            }

LABEL_x22C99:
            v136 = v147;
            v135 = v146;
            v274 = v133[0x22];
            v149 = v147;
            v148 = 0;
            v150 = v146;
            if ( !v274 )
                goto LABEL_x202DC;

LABEL_x22C56:
            v298 = (_DWORD *)((char *)v144 + v274);
            v410 = (char *)v144 + (unsigned int)v298[8];
            v411 = v298 + 7;

LABEL_x200E0:
            v412 = (char *)v144 + *v411;
            v413 = (char *)v144 + (unsigned int)v298[9];

LABEL_x22E6F:
            v275 = v298[6];
            v149 = v136;
            v148 = 0;
            v150 = v135;
            if ( v275 )
            {
LABEL_x20EDE:
                v414 = v275;
                v323 = 0;
                while ( 1 )
                {
LABEL_x20F06:
                    v299 = v323;
                    v300 = (char *)v104
                         + *(unsigned int *)&v412[4 * *(unsigned __int16 *)&v413[2 * v323]];

LABEL_x22C3A:
                    if ( v300 )
                    {
LABEL_x22412:
                        v324 = (unsigned __int8 *)v144 + *(unsigned int *)&v410[4 * v299];
                        v325 = 0xCBF29CE484222325uLL;
                        do
                        {
LABEL_x21AAE:
                            v415 = v325;
                            v416 = v324 + 1;
                            v5 = *v324;
                            v55 = v5 == 0;
                            v417 = v5 ^ v325;

LABEL_x218A3:
                            v324 = v416;
                            v325 = 0x100000001B3LL * v417;
                            v428 = v415;
                        }
                        while ( !v55 );

LABEL_x229B9:
                        v431 = v300;
                        if ( v428 == 0xED1006223ABBBD53uLL )
                        {
LABEL_x21329:
                            v326 = v135;
                            v327 = v136;
                            v328 = (void (__fastcall *)(_QWORD, _QWORD, _QWORD, _QWORD))v431;

LABEL_x216AC:
                            v67 = (void (__fastcall *)(__int64, __int64, _QWORD, unsigned int *))v328;
                            v68 = (void (__fastcall *)(_QWORD, __int64 (__fastcall *)(), __int64 *))v327;
                            v69 = (__int64 (__fastcall *)(__int64, __int64 *))v326;
                            v70 = 0;
                            v148 = v328;
                            v149 = v327;
                            v150 = v326;
                            if ( !v16 )
                                goto LABEL_x2585D;

                            break;
                        }
                    }

LABEL_x21BA2:
                    v323 = v299 + 1;
                    v326 = v135;
                    v327 = v136;
                    v328 = 0;
                    if ( v299 + 1 == v414 )
                        goto LABEL_x216AC;
                }
            }

LABEL_x202DC:
            v139 = v150;
            v138 = v149;
            v137 = v148;
            v276 = v133[0x22];
            v67 = (void (__fastcall *)(__int64, __int64, _QWORD, unsigned int *))v148;
            v68 = (void (__fastcall *)(_QWORD, __int64 (__fastcall *)(), __int64 *))v149;
            v69 = (__int64 (__fastcall *)(__int64, __int64 *))v150;
            v70 = 0;
            if ( v276 )
            {
LABEL_x21044:
                v143 = (_DWORD *)((char *)v144 + v276);
                v418 = (char *)v144 + (unsigned int)v143[8];

LABEL_x2042A:
                v419 = (char *)v144 + (unsigned int)v143[7];
                v420 = (unsigned int)v143[9];

LABEL_x21AF5:
                v421 = (char *)v144 + v420;
                v277 = v143[6];
                v67 = (void (__fastcall *)(__int64, __int64, _QWORD, unsigned int *))v137;
                v68 = (void (__fastcall *)(_QWORD, __int64 (__fastcall *)(), __int64 *))v138;
                v69 = (__int64 (__fastcall *)(__int64, __int64 *))v139;
                v70 = 0;
                if ( v277 )
                {
LABEL_x20E77:
                    v422 = v277;
                    v329 = 0;
                    while ( 1 )
                    {
LABEL_x209BE:
                        v301 = v329;
                        v302 = (char *)v104
                             + *(unsigned int *)&v419[4 * *(unsigned __int16 *)&v421[2 * v329]];

LABEL_x21BFC:
                        if ( v302 )
                        {
LABEL_x20E9F:
                            v330 = (unsigned __int8 *)v144 + *(unsigned int *)&v418[4 * v301];
                            v331 = 0xCBF29CE484222325uLL;
                            do
                            {
LABEL_x21C75:
                                v303 = v331;
                                v423 = v330 + 1;
                                v25 = *v330;
                                v56 = *v330 == 0;

LABEL_x21366:
                                v330 = v423;
                                v331 = 0x100000001B3LL * (v303 ^ v25);
                                v429 = v303;
                            }
                            while ( !v56 );

LABEL_x21B6D:
                            v430 = (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD, _QWORD))v302;
                            if ( v429 == 0xFA55E32C9D72A921uLL )
                            {
LABEL_x20BBA:
                                v67 = (void (__fastcall *)(__int64, __int64, _QWORD, unsigned int *))v137;
                                v68 = (void (__fastcall *)(_QWORD, __int64 (__fastcall *)(), __int64 *))v138;
                                v69 = (__int64 (__fastcall *)(__int64, __int64 *))v139;
                                v70 = v430;
                                goto LABEL_x2585D;
                            }
                        }

LABEL_x2193B:
                        v67 = (void (__fastcall *)(__int64, __int64, _QWORD, unsigned int *))v137;
                        v68 = (void (__fastcall *)(_QWORD, __int64 (__fastcall *)(), __int64 *))v138;
                        v69 = (__int64 (__fastcall *)(__int64, __int64 *))v139;
                        v70 = 0;
                        v329 = v301 + 1;
                        if ( v301 + 1 == v422 )
                            goto LABEL_x2585D;
                    }
                }
            }
        }
    }

LABEL_x2585D:
    v336 = v70;
    v283 = v69;
    v282 = v68;
    v281 = v67;
    v151 = 0xF9E51123;
    v156 = 0xF9E51123;

LABEL_x1DFFC:
    v157 = __ROL4__(v156 + 0x18FD5FCF, 4);

LABEL_x23BAC:
    v282((v157 ^ 0xE5F836DD) + 0x3420C60A, eidolon_run, &v332);
    v105 = v332;

LABEL_x2504F:
    v440 = *(int *)(v105 + 0x3C);
    v127 = (_DWORD *)(v440 + v105);

LABEL_x255E3:
    v435 = v127[0x14];
    v441 = v435;

LABEL_x1DF35:
    v2 = 0;
    if ( *v127 == 0x4550 )
        v2 = v127;

    v337 = v2;
    v72 = *((_WORD *)v2 + 3);

LABEL_x251AE:
    v12 = v337 + 0x42;
    if ( !v337 )
        v12 = 0;

    v442 = v72;
    v284 = v12;
    for ( k = 0; ; k = k_1 + 1 )
    {
LABEL_x25532:
        k_1 = k;

LABEL_x243B4:
        v128 = &v284[0xA * k_1];
        if ( *v128 != 0x2E )
            continue;

LABEL_x2576C:
        if ( v128[1] != 0x65 )
            continue;

LABEL_x1D6C1:
        if ( v128[2] != 0x69 )
            continue;

LABEL_x256CB:
        if ( v128[3] == 0x64 )
            break;

LABEL_x2319C:
        ;
    }

LABEL_x232D1:
    v10 = v128[4] == 0;
    k_2 = k_1;
    if ( !v10 )
        goto LABEL_x2319C;

LABEL_x24B42:
    v285 = v105 + (unsigned int)v284[0xA * k_2 + 3];

LABEL_x1D2E6:
    v152 = 0xEA1474E0;
    v158 = 0xEA1474E0;

LABEL_x20811:
    v159 = __ROL4__((v158 + 0x3DDA20B5) ^ 0x27EE9D95, 0xE);

LABEL_x22299:
    sub_1800C6140(0x3A, 0x61, (unsigned int)v436, 0x24, (int)__ROL4__(v159, 0x1B));

LABEL_x1D255:
    n0x50D591AE = 0x50D591AE;
    n0x50D591AE_1 = 0x50D591AE;
    v286 = v127 + 0x3A;

LABEL_x1D630:
    v154 = 0xC679165A;
    v161 = __ROL4__(0xC679165A, 0x14);

LABEL_x24DC8:
    v162 = ((__ROL4__(v161, 0xE) + 0x631AB01B) ^ 0x75BA3305) - 0x9453A7F;

LABEL_x25437:
    v338 = v127 + 0x3B;
    v339 = (unsigned int)v127[0x3B];
    v340 = v105 + *v286;

LABEL_x23117:
    v281(v340, v339, v162, &v108);
    v163 = *(_DWORD *)(v285 + 0x354);

LABEL_x1D0D8:
    v120 = __ROL4__(v163 + 0x63497614, 7) + 0x37E2891A;
    v106 = v120;

LABEL_x24377:
    v341 = v106 >> 0x18;
    v164 = n0x4C[v106 >> 0x1C] << 0x1C;

LABEL_x24348:
    v165 = n0x4C[((unsigned int)v106 >> 8) & 0xF] << 8;

LABEL_x20781:
    v166 = v164 | v165;
    v30 = n0x4C[v341 & 0xF];

LABEL_x2322D:
    v167 = v166 | (v30 << 0x18);
    v17 = v120;

LABEL_x22E41:
    v168 = v167 | n0x4C[v17 & 0xF];

LABEL_x1D08E:
    v342 = v106 >> 0x10;
    v169 = v168 | (n0x4C[((unsigned int)v106 >> 0x14) & 0xF] << 0x14);

LABEL_x2468E:
    v170 = v169 | (0x10 * n0x4C[v17 >> 4]);

LABEL_x1FFCA:
    v171 = n0x4C[(unsigned __int16)v106 >> 0xC] << 0xC;

LABEL_x1D1BC:
    v172 = v171 | v170;
    v31 = n0x4C[v342 & 0xF];

LABEL_x23FBF:
    v173 = dword_180281EAA ^ __ROL4__(v172 | (v31 << 0x10), 1);

LABEL_x1D452:
    v109 = v173;
    sub_18011CC30(0x36, 0x1B, 6, &v109);
    v174 = v109;

LABEL_x251F5:
    v141 = v285;
    v129 = (int *)(v285 + 0x35C);
    v175 = *(_DWORD *)(v285 + 0x35C);

LABEL_x2554F:
    v110 = (v175 ^ 0xCA) + 0x3C29488A;
    sub_180145D40(0x27, &v110, 0x3A, 0xE);

LABEL_x247DD:
    v176 = qword_180281BA7 ^ __ROL4__(v110, 0xE) ^ 0x3ED8A0A3;

LABEL_x24739:
    v130 = v336(0, 0x10LL * (unsigned int)(v176 - 0x440E4F90), 0x3000, 4);

LABEL_x20681:
    v343 = &v437;
    v344 = &v438;

LABEL_x236C9:
    v177 = (*v129 ^ 0xCA) + 0x3C29488A;

LABEL_x250C0:
    v57 = v177;
    sub_180145D40(0x1C, &v57, 4, 0x35);
    v178 = __ROL4__(v57, 5);

LABEL_x1D42A:
    if ( ((unsigned int)qword_180281BA7 ^ __ROL4__(v178, 9)) != 0x7AD6EF33 )
    {
LABEL_x1F17B:
        v345 = v174 ^ 0x3447395BLL;

LABEL_x2426B:
        v346 = v141 + v345;
        v179 = __ROL4__(n0x50D591AE_1 - 0x331780D2, 0x1E);

LABEL_x1D9FB:
        v309 = (int)__ROL4__(v179 ^ 0x76F8437, 0x1E);
        v310 = v346;
        v311 = 0;

LABEL_x1EFE6:
        do
        {
            v288 = v311;
            v66 = v310;
            v287 = v309;
            v347 = (int *)(v310 + 0xC);
            v180 = *(_DWORD *)(v310 + 0xC);

LABEL_x21F5E:
            v181 = __ROL4__((v180 ^ 0x104D2D6B) + 0x9424889, 0x10);

LABEL_x1D77F:
            v121 = *(_DWORD *)((char *)&qword_180281C6C + 6);
            v0 = (unsigned int)((*(_DWORD *)((char *)&qword_180281C6C + 6) ^ __ROL4__(v181, 0x17))
                              + 0x59E3C315);
            v182 = v0;
            v107 = v0;

LABEL_x1D498:
            v348 = v107 >> 8;
            v183 = n0x4C_0[(unsigned __int16)v107 >> 0xC];

LABEL_x1D5E5:
            v184 = v183 << 0xC;
            v349 = v107 >> 0x18;
            v185 = n0x4C_0[v107 >> 0x1C];

LABEL_x1D96A:
            v186 = v184 | (v185 << 0x1C);
            v350 = &n0x4C_0[v349 & 0xF];

LABEL_x1EBBC:
            v187 = v186 | (*v350 << 0x18);

LABEL_x2499F:
            v188 = v187 | (n0x4C_0[BYTE2(v107) & 0xF] << 0x10);

LABEL_x252A7:
            v32 = n0x4C_0[v348 & 0xF];

LABEL_x1D8FB:
            v189 = v188 | (v32 << 8);
            v33 = v182;
            v351 = (unsigned __int8)v182 >> 4;

LABEL_x1F039:
            v190 = v189 | (0x10 * n0x4C_0[v351]);

LABEL_x1D500:
            v34 = n0x4C_0[v33 & 0xF];

LABEL_x23737:
            v191 = v190 | v34;
            v35 = n0x4C_0[((unsigned int)v107 >> 0x14) & 0xF];

LABEL_x248BE:
            v111 = (v191 | (v35 << 0x14)) ^ 0xB3;
            sub_18010D1D0(0x4E, &v111, 5, 0x34);

LABEL_x1D153:
            v352 = v141 + v111;

LABEL_x24806:
            v353 = v352;
            v192 = *(_DWORD *)(v66 + 0x14);

LABEL_x23E7B:
            v114 = v192 - 0x30941AA1;
            sub_180207B30(0x5E, 0xF, 0x5E, &v114);
            v193 = dword_180281B47;

LABEL_x2203F:
            v194 = __ROL4__(__ROL4__(v193 ^ v114, 0x17) ^ 0x1470413F, 0x1E);

LABEL_x1EABF:
            v195 = *v347;

LABEL_x1E67D:
            v196 = __ROL4__((v195 ^ 0x104D2D6B) + 0x9424889, 0x10);

LABEL_x24904:
            v122 = (v121 ^ __ROL4__(v196, 0x17)) + 0x59E3C315;
            v101 = v122;

LABEL_x1F5A0:
            v354 = v101 >> 8;
            v197 = n0x4C_0[(unsigned __int16)v101 >> 0xC] << 0xC;

LABEL_x24E27:
            v355 = v101 >> 0x18;
            v198 = n0x4C_0[v101 >> 0x1C] << 0x1C;

LABEL_x1DAB3:
            v199 = v197 | v198;
            v356 = &n0x4C_0[v355 & 0xF];

LABEL_x2354A:
            v200 = v199 | (*v356 << 0x18);
            v357 = v101 >> 0x10;

LABEL_x20FBA:
            v201 = v200 | (n0x4C_0[v357 & 0xF] << 0x10);

LABEL_x21547:
            v202 = v201 | (n0x4C_0[v354 & 0xF] << 8);

LABEL_x21D78:
            v18 = v122;
            v36 = n0x4C_0[(unsigned __int8)v122 >> 4];

LABEL_x239EA:
            v203 = v202 | (0x10 * v36);

LABEL_x1DF6A:
            v204 = v203 | n0x4C_0[v18 & 0xF];

LABEL_x25019:
            v205 = v204 | (n0x4C_0[((unsigned int)v101 >> 0x14) & 0xF] << 0x14);

LABEL_x21E07:
            v112 = v205 ^ 0xB3;
            sub_18010D1D0(0x1A, &v112, 0x3A, 0x56);
            v206 = v112;

LABEL_x1DE02:
            v123 = *(_DWORD *)(v66 + 0x20);

LABEL_x1F344:
            v131 = v123;
            v358 = v123 >> 8;
            v359 = (unsigned __int16)v123 >> 0xC;

LABEL_x241BF:
            v207 = n0x4C_1[v359] << 0xC;
            v360 = v131 >> 0x18;

LABEL_x1D935:
            v208 = v207 | (n0x4C_1[v131 >> 0x1C] << 0x1C);

LABEL_x1D384:
            v37 = v123;
            v209 = v208 | n0x4C_1[v123 & 0xF];

LABEL_x24CB7:
            v361 = v131 >> 0x10;
            v362 = &n0x4C_1[((unsigned int)v131 >> 0x14) & 0xF];

LABEL_x23160:
            v210 = v209 | (*v362 << 0x14);
            v363 = v360 & 0xF;

LABEL_x1F5E3:
            v211 = v210 | (n0x4C_1[v363] << 0x18);

LABEL_x246BF:
            v212 = v211 | (n0x4C_1[v358 & 0xF] << 8);

LABEL_x23EC5:
            v213 = n0x4C_1[v37 >> 4];

LABEL_x1EDCD:
            v214 = v212 | (0x10 * v213);
            v364 = &n0x4C_1[v361 & 0xF];

LABEL_x1E9C9:
            v113 = ((v214 | (*v364 << 0x10)) + 0x71DCDC6A) ^ 0xA70B480C;

LABEL_x23023:
            sub_18011C8C0(0x3F, 0x59, &v113, 0x39);
            v215 = qword_180281BFA ^ (__ROL4__(v113, 0x11) + 0x34B92CEE);

LABEL_x22941:
            v216 = __ROL4__(v215 ^ 0x64, 0x14);
            v365 = (_WORD *)(v66 + 0x18);

LABEL_x24C41:
            v73 = *v365 ^ 0xC0;

LABEL_x24A14:
            v59 = v73;
            sub_1800A9E50(0x2D, 0x35, &v59, 0x17);
            v74 = (v59 - 0xE15) ^ 0xF50;

LABEL_x1D30C:
            v63 = __ROL2__(v74, 0xA);
            v19 = HIBYTE(v63);

LABEL_x1ED3A:
            v75 = n0x4C_2[v19 & 0xF] << 8;

LABEL_x1E79C:
            v76 = n0x4C_2[v19 >> 4] << 0xC;

LABEL_x24835:
            v77 = v75 | v76;
            v20 = v63;
            v366 = v63 & 0xF;

LABEL_x1F3CF:
            v78 = v77 | n0x4C_2[v366];
            v38 = v20 >> 4;

LABEL_x24466:
            v79 = v78 | (0x10 * n0x4C_2[v38]);

LABEL_x2059F:
            v4 = v79;
            LOWORD(v4) = __ROL2__(word_18028220F ^ v79, 3);
            if ( !(unsigned __int8)sub_1800D1720(
                                       0x3B,
                                       v4 - 0x3A89,
                                       4,
                                       v216,
                                       v353,
                                       v206,
                                       v194,
                                       (__int64)v445) )
                break;

LABEL_x220A1:
            v155 = 0xFF702F9C;
            v223 = 0xFF702F9C;

LABEL_x1F670:
            v224 = __ROL4__((v223 ^ 0x54CAEA40) + 0x2369CFF3, 0x16) - 0x73F3C923;

LABEL_x2361F:
            v282(v224, (__int64 (__fastcall *)())v445, &v278);
            v289 = (_WORD *)(v66 + 0x10);
            v80 = *(_WORD *)(v66 + 0x10);

LABEL_x2413E:
            v64 = __ROL2__(v80 + 0x7614, 7) - 0x76E6;

LABEL_x24BCF:
            v39 = v64;
            v40 = n0x4C[(unsigned __int8)v64 >> 4];

LABEL_x1FE27:
            v81 = 0x10 * v40;
            v368 = v39 & 0xF;

LABEL_x1DEF9:
            v82 = v81 | n0x4C[v368];
            v21 = HIBYTE(v64);

LABEL_x1E2EE:
            v83 = n0x4C[v21 & 0xF] << 8;

LABEL_x22FB2:
            v84 = v83 | v82;
            v85 = n0x4C[v21 >> 4];

LABEL_x201CC:
            n0x4C = n0x4C_3;
            n0x395B = n0x4C_3 ^ __ROL2__(v84 | (v85 << 0xC), 1);

LABEL_x2405C:
            sub_1801C72E0(0x5E, 0x1A, &n0x395B, 0x4E);
            if ( n0x395B == 0x395B )
            {
LABEL_x1F6CB:
                v377 = (unsigned int *)(v66 + 4);
                n0x4C_6 = *(_DWORD *)(v66 + 4);

LABEL_x22708:
                n0x4C_1 = n0x4C_6;
                sub_180184060(0x24, 0x36, 0x11, &n0x4C_1);
                n0x4C_2 = n0x4C_1;
                n0x4C_3 = n0x4C_1;

LABEL_x22F72:
                v378 = n0x4C_3 >> 8;
                v233 = n0x4C_4[(unsigned __int16)n0x4C_3 >> 0xC];

LABEL_x1DC85:
                v234 = v233 << 0xC;
                v379 = n0x4C_3 >> 0x10;
                v380 = n0x4C_3 >> 0x14;

LABEL_x1E1B0:
                v235 = v234 | (n0x4C_4[v380 & 0xF] << 0x14);

LABEL_x1F69D:
                n0x4C_4 = n0x4C_2;
                v236 = n0x4C_4[(unsigned __int8)n0x4C_2 >> 4];

LABEL_x1FAA5:
                v237 = v235 | (0x10 * v236);
                v381 = n0x4C_3 >> 0x18;

LABEL_x1E5F9:
                v238 = v237 | (n0x4C_4[v381 & 0xF] << 0x18);

LABEL_x1E9FC:
                v239 = v238 | (n0x4C_4[v379 & 0xF] << 0x10);

LABEL_x23841:
                v45 = n0x4C_4[n0x4C_4 & 0xF];

LABEL_x238FE:
                v240 = v239 | v45;
                v382 = &n0x4C_4[v378 & 0xF];

LABEL_x1F453:
                v241 = v240 | (*v382 << 8);
                v383 = n0x4C_3 >> 0x1C;

LABEL_x23AB3:
                v242 = (v241 | (n0x4C_4[v383] << 0x1C)) ^ 0x35;

LABEL_x23F8E:
                v243 = __ROL4__(
                           dword_180281CC9 ^ ((__ROL4__(v242, 0x15) ^ 0xC29D9565) - 0x7F75452F),
                           9);

LABEL_x245F2:
                v384 = v141 + v243;

LABEL_x2157B:
                v244 = *(_DWORD *)(v66 + 8);

LABEL_x243EB:
                v124 = qword_180281C46 ^ (v244 - 0x2412DBD0);

LABEL_x1E91D:
                v132 = v124;
                v385 = v124 >> 8;
                v386 = &n0x4C_5[(unsigned __int16)v124 >> 0xC];

LABEL_x23E19:
                v245 = *v386 << 0xC;
                v46 = v124;
                v47 = v124 & 0xF;

LABEL_x2174F:
                v246 = v245 | n0x4C_5[v47];
                v48 = v46 >> 4;

LABEL_x1EE5B:
                v247 = v246 | (0x10 * n0x4C_5[v48]);

LABEL_x2151A:
                v248 = n0x4C_5[BYTE2(v132) & 0xF] << 0x10;

LABEL_x1E53E:
                v249 = v248 | v247;
                v387 = BYTE3(v132) & 0xF;

LABEL_x24099:
                v250 = v249 | (n0x4C_5[v387] << 0x18);

LABEL_x240CA:
                v251 = v250 | (n0x4C_5[v385 & 0xF] << 8);

LABEL_x1F28C:
                v252 = v251 | (n0x4C_5[((unsigned int)v132 >> 0x14) & 0xF] << 0x14);

LABEL_x23773:
                v253 = v252 | (n0x4C_5[v132 >> 0x1C] << 0x1C);

LABEL_x22451:
                v254 = __ROL4__(__ROL4__(v253, 0x10) ^ 0x2255760A, 0xD);

LABEL_x22375:
                v118 = v254;
                sub_1800EC750(&v118, 2, 2, 0x28);
                v255 = v118 + 0x1772935;

LABEL_x1E125:
                p_n0x4C = *v377;

LABEL_x1E4AF:
                sub_180184060(8, 0x42, 0x1D, &p_n0x4C);
                p_n0x4C_1 = p_n0x4C;
                p_n0x4C_2 = p_n0x4C;

LABEL_x208F3:
                v388 = p_n0x4C_2 >> 8;
                v257 = n0x4C_4[(unsigned __int16)p_n0x4C_2 >> 0xC];

LABEL_x20AD9:
                v258 = v257 << 0xC;
                v389 = p_n0x4C_2 >> 0x10;
                v390 = &n0x4C_4[((unsigned int)p_n0x4C_2 >> 0x14) & 0xF];

LABEL_x1F7D3:
                v259 = v258 | (*v390 << 0x14);

LABEL_x1E80B:
                p_n0x4C_3 = p_n0x4C_1;
                v260 = 0x10 * n0x4C_4[(unsigned __int8)p_n0x4C_1 >> 4];

LABEL_x239AE:
                v261 = v260 | v259;
                v49 = n0x4C_4[BYTE3(p_n0x4C_2) & 0xF];

LABEL_x1ECC2:
                v262 = v261 | (v49 << 0x18);
                v391 = v389 & 0xF;

LABEL_x21872:
                v263 = v262 | (n0x4C_4[v391] << 0x10);

LABEL_x1FCC8:
                v264 = v263 | n0x4C_4[p_n0x4C_3 & 0xF];

LABEL_x237A8:
                v265 = v264 | (n0x4C_4[v388 & 0xF] << 8);

LABEL_x235EA:
                v266 = v265 | (n0x4C_4[p_n0x4C_2 >> 0x1C] << 0x1C);

LABEL_x22FF2:
                v267 = dword_180281CC9 ^ ((__ROL4__(v266 ^ 0x35, 0x15) ^ 0xC29D9565) - 0x7F75452F);

LABEL_x1F881:
                v268 = __ROL4__(v267, 9);
                v392 = (_DWORD *)(v66 + 0x1C);

LABEL_x1EA98:
                v269 = qword_180281AD3 ^ __ROL4__(*v392, 6);

LABEL_x1FFF9:
                v117 = (v269 ^ 0xFF) - 0x633E3B15;
                sub_1800BA0C0(&v117, 1, 0x4D, 0x5A);

LABEL_x23D8A:
                v270 = (__ROL4__(v117, 3) ^ 0xA63218BF) + 0x64312B02;

LABEL_x203C7:
                v94 = __ROL2__(*(_WORD *)v66 + 0x7614, 7);

LABEL_x1F745:
                v65 = v94 - 0x76E6;
                v50 = v94 + 0x1A;
                v393 = (unsigned __int8)(v94 + 0x1A) >> 4;

LABEL_x219E3:
                v95 = 0x10 * n0x4C[v393];
                v51 = v50 & 0xF;

LABEL_x20DDA:
                v96 = v95 | n0x4C[v51];

LABEL_x21217:
                v24 = HIBYTE(v65);
                v52 = n0x4C[HIBYTE(v65) & 0xF];

LABEL_x21A19:
                v97 = v96 | (v52 << 8);
                v394 = v24 >> 4;

LABEL_x218F6:
                v98 = __ROL2__(v97 | (n0x4C[v394] << 0xC), 1);
                n0x4C_5 = n0x4C_3;

LABEL_x20CD7:
                v62 = n0x4C_5 ^ v98;
                sub_1801C72E0(9, 8, &v62, 0x37);
                v100 = v62;

LABEL_x22B5D:
                if ( !(unsigned __int8)sub_1800D1720(
                                           0x53,
                                           v100 ^ 0x395Bu,
                                           0x29,
                                           v270,
                                           v384,
                                           v268,
                                           v255,
                                           (__int64)v444) )
                    break;

LABEL_x22A38:
                n0x5F = v283(v278, v444);
            }
            else
            {
LABEL_x24568:
                v87 = *v289 + 0x7614;

LABEL_x1D87A:
                v1 = __ROL2__(v87, 7);
                v88 = v1 - 0x76E6;
                v22 = v1 + 0x1A;
                v41 = (unsigned __int8)(v1 + 0x1A) >> 4;

LABEL_x1D4D8:
                v89 = 0x10 * n0x4C[v41];

LABEL_x20208:
                v90 = v89 | n0x4C[v22 & 0xF];

LABEL_x208C8:
                v42 = HIBYTE(v88);
                v43 = n0x4C[HIBYTE(v88) & 0xF];

LABEL_x2225A:
                v91 = v90 | (v43 << 8);
                v369 = &n0x4C[v42 >> 4];

LABEL_x20C37:
                v92 = n0x4C ^ __ROL2__(v91 | (*v369 << 0xC), 1);

LABEL_x22107:
                v60 = v92;
                sub_1801C72E0(0x20, 0x45, &v60, 0x58);
                v93 = v60;

LABEL_x210D7:
                v370 = v93 ^ 0x395BLL;
                v371 = v278;

LABEL_x233E3:
                n0x5F = v283(v371, (__int64 *)v370);
            }

LABEL_x1D659:
            n0x5F_1 = n0x5F;
            v290 = v287 + *(_QWORD *)v343;
            v373 = sub_1800D2ED0(0x49, 0x43, 0x37, n0x5F, *(_QWORD *)v344 + v287);

LABEL_x1E097:
            v374 = v287 + v373;
            v225 = *(_DWORD *)(v66 + 0x24);

LABEL_x20A4C:
            v119 = v225;
            sub_18016E9A0(&v119, 0x4B, 0x46, 2);
            v226 = v119;

LABEL_x1E8EF:
            v227 = qword_180281BE0 ^ __ROL4__((v226 + 0x1101C288) ^ 0xF68B1802, 0xC);

LABEL_x225E8:
            *(_QWORD *)(v105 + (unsigned int)__ROL4__(v227, 1)) = v290;

LABEL_x227F5:
            v6 = v130;
            v7 = 0x10 * v288;
            *(_QWORD *)(v130 + v7) = v290;
            *(_QWORD *)(v6 + v7 + 8) = n0x5F_1;
            v375 = v288 + 1;

LABEL_x20520:
            v376 = v66 + 0x28;
            v228 = *v129;

LABEL_x22D81:
            v57 = (v228 ^ 0xCA) + 0x3C29488A;

LABEL_x2253C:
            sub_180145D40(0x3B, &v57, 0x23, 0x2B);
            v229 = __ROL4__(v57, 0xE);
            v230 = qword_180281BA7;

LABEL_x1F502:
            v309 = v374;
            v310 = v376;
            v311 = v375;
        }
        while ( v375 < (v229 ^ v230 ^ 0x3ED8A0A3u) - 0x440E4F90 );
    }

LABEL_x24B02:
    v281(v105 + *v286, *v338, v108, &v108);

LABEL_x1DB7B:
    sub_180196E90(0x32, 0x53, 0x3C, v436);
    v217 = *v129;

LABEL_x23C68:
    v58 = (v217 ^ 0xCA) + 0x3C29488A;
    sub_180145D40(7, &v58, 0x1B, 0x2C);

LABEL_x23CAB:
    v218 = __ROL4__(v58, 0xE);
    v219 = qword_180281BA7;

LABEL_x24DF5:
    v312 = 0;
    if ( (v218 ^ v219) != 0x7AD6EF33 )
    {
        do
        {
LABEL_x24EE1:
            v142 = v312;
            sub_1801C7700(
                0xA,
                *(_QWORD *)(v130 + 0x10 * v312),
                *(_QWORD *)(v130 + 0x10 * v312 + 8),
                0x47,
                0x47);

LABEL_x24537:
            v367 = v142 + 1;
            v220 = *v129;

LABEL_x1E3F2:
            v58 = (v220 ^ 0xCA) + 0x3C29488A;
            sub_180145D40(0x35, &v58, 0x25, 0x47);
            v221 = v58;

LABEL_x23E4D:
            v222 = (qword_180281BA7 ^ __ROL4__(v221, 0xE) ^ 0x3ED8A0A3) - 0x440E4F90;

LABEL_x2088E:
            v312 = v367;
        }
        while ( v367 < v222 );
    }

    return ((__int64 (__fastcall *)(_QWORD))(&byte_18027B8E0 + 0x7A))(v130);
}