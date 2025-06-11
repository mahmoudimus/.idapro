

```cpp
ObjectMgr::g_stateAddr = read_offset(pattern::find("48 8B 3D ?? ?? ?? ?? 4C 89 75 28"), 3, 7);
ObjectMgr::g_taintAddr = read_offset(pattern::find("4C 8B 05 ? ? ? ? 48 8D 15 ? ? ? ? 48 8D 8D"), 3, 7);
ObjectMgr::g_strtoguid_fn = read_offset(pattern::find("E8 ?? ?? ?? ?? 3B C3 75 23"), 1, 5);
ObjectMgr::g_entityindex_fn = pattern::find("48 89 5C 24 ? 57 48 83 EC ? 48 8B 1D ? ? ? ? 48 8B F9 4C 8B C2");
ObjectMgr::g_objectMgrAddr = read_offset(ObjectMgr::g_entityindex_fn + 0xA, 3, 7);
ObjectMgr::g_questnpcAddr = read_offset(pattern::find("48 8D 05 ?? ?? ?? ?? 48 C1 E9 3A 48 8D 15 ?? ?? ?? ?? 84 C9"), 3, 7);
ObjectMgr::g_currentFrameAddr = read_offset(pattern::find("48 8B 0D ?? ?? ?? ?? C6 05"), 3, 7);
ObjectMgr::g_traceline_fn = read_offset(pattern::find("E8 ?? ?? ?? ?? 84 C0 74 ?? 40 84 FF 0F 84"), 1, 5);
ObjectMgr::g_localplayerAddr = read_offset(pattern::find("0F 28 05 ? ? ? ? 48 8B C3 0F 11 03 48 83 C4 40"), 3, 7);
```

they removed all the debughooks from the binary but they left all the actual code in precall/postcall.
if you manually change the data in the state, your hook gets called.

```cpp
void callback(lua_State* L, lua_Debug* ar) {
    // --- one‐time startup log ---
    static bool once = true;
    if (once) {
        log("[Hook] Success", LogLevel::Info);
        once = false;
    }

    if (!L || !ar) {
        return;
    }

    // Fetch function name, source, etc.
    lua_getinfo(L, "nSlu", ar);

    CallInfo*  ci = L->ci;
    StkId      func = ci->func;
    StkId      top = L->top;

    // Dispatch “return hook” vs “call hook”
    if (ar->event == LUA_HOOKRET) {
        // We returned from some Lua function.
        if (helpers::is_function(L, ar, "CastSpellByID")) {
            onReturn_CastSpellByID(L);
        }
        else if (helpers::is_function(L, ar, "UnitPosition")) {
            onReturn_UnitPosition(L, func);
        }
        else if (helpers::is_function(L, ar, "RunMacroText") || helpers::is_function(L, ar, "RunScript"))
        {
            set_taint(0);
            *reinterpret_cast<int*>(ObjectMgr::g_taintAddr + 0xC) = 0;
        }
    }
    else {
        // LUA_HOOKCALL
        if (helpers::is_function(L, ar, "CastSpellByID")) {
            onCall_CastSpellByID(L, func, top);
        }
        else if (helpers::is_function(L, ar, "RunMacroText") || helpers::is_function(L, ar, "RunScript"))
        {
           set_taint(1);
        }
    }
}

//  what that does is if i pass a GUID as the unit, it writes it to questnpc and updates the arg to 'questnpc'
// can cast on GUIDS
static void onCall_CastSpellByID(lua_State* L, StkId func, StkId top) {
    int nargs = helpers::count_args(func, top);
    if (nargs < 2) {
        return;
    }

    // Arg#1 = spellID, Arg#2 = unit string
    auto spellID = helpers::get_arg_number(func, 1);
    const char* unit = helpers::get_arg_string(func, 2);
    if (auto obj = ObjectMgr::GetObjectByGuid(unit)) {
        // Mark quest NPC and rewrite argument #2
        ObjectMgr::set_questnpc_guid(unit);
        helpers::replace_arg_with_cstring(L, func, 2, "questnpc");

        // Log for debugging
        logf(LogLevel::Info,
            "[HOOK] Object[%s] -> 0x%08X",
            unit,
            reinterpret_cast<uintptr_t>(obj));
    }

    set_taint(1);
}

// I built this with melee in mind, so il use nameplates. That being said, the game has a UnitPosition 
// function it just dosnt work on all units. SInce I hooked it, i just update the return values with 
// real data if its called with a guid
static void onReturn_UnitPosition(lua_State* L, StkId func) {
    const char* unit = helpers::get_arg_string(func, 1);
    if (auto obj = ObjectMgr::GetObjectByGuid(unit)) {
        Vector3 pos;
        obj->GetUnitPosition(&pos);

        // Pop the original 4 return-values
        lua_pop(L, 4);

        // Push (X, Y, Z, los)
        lua_pushnumber(L, pos.X);
        lua_pushnumber(L, pos.Y);
        lua_pushnumber(L, pos.Z);
        bool hasLOS = ObjectMgr::traceline(ObjectMgr::local_player(), obj).los;
        lua_pushnumber(L, hasLOS ? 1 : 0);
    }
}
```