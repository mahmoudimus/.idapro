

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


```c++
//His state is different then mine 
//I dont have these:
//    lu_byte taintflags; /* user-controlled taint propagation mode flags /
//    TStringstacktaint; /* current stack taint /
//    TStringwritetaint; /* taint applied to values on stack writes /
//    TStringfixedtaint; /* taint applied from currently executing Lua closure /
//    TStringnewgctaint; /* taint applied to newly allocated objects /
//    TStringnewcltaint; /* taint applied to newly allocated closures */
// [6:10 PM]Aceolust: his commonheader is right though
// [6:10 PM]Aceolust: there are some changes to Closures too
// [6:11 PM]Aceolust: I used AI to some extent. I went and i found all the lua_ functions like pushnumber etc. I gave them to AI and asked it to rebuild the structures it got pretty close

struct __declspec(align(8)) lua_State
{
    CommonHeader;
    __int64 taintCryptoValue;
    char status;
    TValue* top;
    TValue* base;
    global_State* l_G;
    CallInfo* ci;
    const unsigned int* savedpc;
    TValue* stack_last;
    TValue* stack;
    CallInfo* end_ci;
    CallInfo* base_ci;
    int stacksize;
    int size_ci;
    unsigned __int16 nCcalls;
    unsigned __int16 baseCcalls;
    unsigned __int8 hookmask;
    unsigned __int8 allowhook;
    int basehookcount;
    int hookcount;
    void(__fastcall* hook)(lua_State*, lua_Debug*);
    TValue l_gt;
    TValue env;
    GCObject* openupval;
    GCObject* gclist;
    struct lua_longjmp* errorJmp;
    __int64 errfunc;
    int isServerProcessing;
    int unk1;
};
```

```c++
// finding mapped ntdll
bool findMappedNTDLL()
{
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);

    MEMORY_BASIC_INFORMATION region;
    for (region.BaseAddress = systemInfo.lpMinimumApplicationAddress;
        region.BaseAddress < systemInfo.lpMaximumApplicationAddress
            && VirtualQuery(region.BaseAddress, &region, region.sizeof);
        region.BaseAddress += region.RegionSize)
    {
        if (region.State == MEM_COMMIT
            && region.Protect == PAGE_EXECUTE_READWRITE
            && region.RegionSize > 0x80000)
        {
            log!"Found mapped NTDLL at %X with size %X"(cast(size_t) region.BaseAddress, region.RegionSize);
            mappedNTDLLBaseAddress = region.BaseAddress;
            mappedNTDLLSize = region.RegionSize;
            return true;
        }
    }

    log!"Did not find mapped NTDLL.";
    return false;
}
```

```c++

/*
[1:08 PM]Aceolust: i save the target object, spell and if its a AOE spell ( green circle on ground)
[1:08 PM]Aceolust: if it is as soon as the call returns, i click the objects position using HandleTerrainClick
[5:34 PM]alg0rithm: oh hold up
[5:34 PM]alg0rithm: i see what you're doing
[5:34 PM]alg0rithm: are you just finidng the lua state
[5:34 PM]alg0rithm: and just hooking certain parts
[5:34 PM]alg0rithm: and then having that call your functions instead?
[5:37 PM]Aceolust: sort of, its hard to explain without havning a bit of understanding how the game and the lua functions work. 

Basically CastSpellByID or Name take a spell ID or Name and what wow calls a unit token. That unit token list is hardcoded. player,target,targettarget,focus all representing unit frames on your screen. What my code does is allows me to pass the GUID of a unit( one i may not have targeted or selected in someway). Assign it to the questnpc token , switch the second arg from GUID to questnpc token and then let the call proceed
[5:37 PM]Aceolust: The use case is like, im fighting 5 mobs and one of them starts casting a spell i can iunterupt
[5:38 PM]Aceolust: instead of having to target them, i can now just quickly cast my interuppt on them without ever changing my main target
[5:42 PM]Aceolust: The other thing is wow has protected functions, castspellbyname/ID are examples of those
[5:55 PM]alg0rithm: i understand what your code snippet above did
[5:56 PM]alg0rithm: but you are hooking CastSpellByID to call onCall_CastSpellByID directly ?
[5:56 PM]Aceolust: no
[5:56 PM]alg0rithm: oh how is that being invoked then?
[5:58 PM]Aceolust: I used this

https://fxcodebase.com/bin/products/IndicoreSDK/3.4.0/help/Lua/lua/lua_sethook.html

Blizzard actually removed that function from their version of LUA but they didnt remove all the fields in the data structures. 

    unsigned __int16 nCcalls;
    unsigned __int16 baseCcalls;
    unsigned __int8 hookmask;
    unsigned __int8 allowhook;
    int basehookcount;
    int hookcount;
    void(__fastcall* hook)(lua_State*, lua_Debug*);
    TValue l_gt;
    TValue env;
[5:59 PM]Aceolust: so i can set them directly and the hook still functions, it hooks every single lua call
[5:59 PM]Aceolust: or whatever else you want based on the mask you give it
[5:59 PM]Aceolust: so yes a hook but not castspellbyname directly
*/
  // Called when we invoke (call‐hook) CastSpellByID(…, …)
  static void onCall_CastSpellByID(lua_State* L, lua_Debug* ar) {

      int newCallId = g_nextCallId++;
      g_castSpellCallStack.push_back(newCallId);
      logf(LogLevel::Info, std::source_location::current(), "CastSpellByID CallID = 0x{:x}", newCallId);
      int nargs = lh::getArgCount(L, ar);
      if (nargs < 2) {
          return;
      }
    
      // Arg#1 = spellID, Arg#2 = unit string
      auto spellID = lh::getArg<lua_Integer>(L, ar, 1);
      auto unit = lh::getArg<const char*>(L, ar, 2);
      if (unit && spellID)
      {
          if (auto obj = ObjectMgr::GetObjectByGuid(unit.value())) {
              // Assign quest NPC and rewrite argument #2
              ObjectMgr::set_questnpc_guid(unit.value());
              lh::setArg(L, ar, 2, "questnpc");

              CastSpellData data;
              data.spellId = spellID.value();
              data.object = obj; 
              data.aoe = true;

              // Store the payload in our map, keyed by the unique callId.
              g_spellDataMap[newCallId] = data;

              // Log for debugging
              logf(LogLevel::Info, 
                  "[HOOK] Object[%s] -> 0x%08X",
                  unit.value(),
                  reinterpret_cast<uintptr_t>(obj)); 
          }
      }

      set_taint(1);
  }
  
   // Called when we return from a CastSpellByID() call
 static void onReturn_CastSpellByID(lua_State* L) {

     if (!g_castSpellCallStack.empty()) {
         int matchedCallId = g_castSpellCallStack.back();
         g_castSpellCallStack.pop_back();
     
         auto it = g_spellDataMap.find(matchedCallId);
         if (it != g_spellDataMap.end()) {
             const CastSpellData& data = it->second;
            
             if (data.object && data.aoe && ObjectMgr::IsSpellTargeting())
             {
                 Vector3 pos;
                 data.object->GetUnitPosition(&pos);
                 ObjectMgr::HandleTerrainClick(pos, 1);
             }
             g_spellDataMap.erase(it);

         }
     }
     set_taint(0);
 }
 ```