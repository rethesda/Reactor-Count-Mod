#include "pch.h"

#include "AoBSwap.h"
#include "Logger.h"
#include "ScanMemory.h"
#include "Util.h"

#include "lib/SFSE/sfse/PluginAPI.h"
#include "lib/SFSE/sfse_common/sfse_version.h"

#define LOG_VERSION(a) GET_EXE_VERSION_MAJOR(a) << "." << GET_EXE_VERSION_MINOR(a) << "." << GET_EXE_VERSION_BUILD(a) << "." << GET_EXE_VERSION_SUB(a)

const std::vector<BYTE> LEA_START = StringToByteVector("48 8D 15");

const std::map<std::string, std::vector<std::string>> TYPE_MAPPING = {
    {"Allow-Unattached-Modules-Mod", {"SB_ERRORBODY_NOT_ATTACHED"}},
    {"BayAndDocker-Count-Mod", {"SB_LIMITBODY_MAX_LANDING_BAY", "SB_LIMITBODY_MAX_DOCKER"}},
    {"Build-Below-Bay-Mod", {"SB_ERRORBODY_MODULE_BELOW_LANDINGBAY", "SB_ERRORBODY_DOCKER_INVALID_POSITION", "SB_ERRORBODY_LANDINGENGINE_NOT_ALIGNED_WITH_LANDINGBAY"}},
    {"Cockpit-Count-Mod", {"SB_LIMITBODY_MAX_COCKPIT"}},
    {"Engine-Power-Mod", {"SB_LIMITBODY_EXCESS_POWER_ENGINE"}},
    //{"GravDrive-Count-Mod", {"SB_LIMITBODY_MAX_GRAV_DRIVE"}}, // Winds up with "you need additional grav thrust".
    {"GravDrive-Weight-Mod", {"SB_ERRORBODY_SHIP_TOO_HEAVY_TO_GRAVJUMP"}},
    {"LandingGear-Count-Mod", {"SB_LIMITBODY_MIN_LANDING_GEAR"}},
    {"Reactor-Class-Mod", {"SB_ERRORBODY_REACTOR_CLASS"}},
    {"Reactor-Count-Mod", {"SB_LIMITBODY_MAX_REACTOR"}},
    {"Shield-Count-Mod", {"SB_LIMITBODY_MAX_SHIELD"}},
    {"Weapon-Power-Mod", {"SB_LIMITBODY_EXCESS_POWER_WEAPON", "SB_LIMITBODY_MAX_WEAPONS"}},
};

const std::map<std::string, std::vector<std::string>> SCAN_MAPPING = {
    {"Allow-Unattached-Modules-Mod", {"75 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D 30"}}, // 75 == `jne`
    {"BayAndDocker-Count-Mod", {"7E ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D C8"}}, // 7E == `jle`
    {"Build-Below-Bay-Mod", {"75 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D 30"}}, // 75 == `jne`
    {"Cockpit-Count-Mod", {"7E ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D D0"}}, // 7E == `jle`
    {"Engine-Power-Mod", {"7E ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D 30"}}, // 7E == `jle`
    //{"GravDrive-Count-Mod", {"7E ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D 50"}}, // 7E == `jle`
    {"GravDrive-Weight-Mod", {"73 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D 30"}}, // 73 == `jae`
    {"LandingGear-Count-Mod", {"75 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D D0"}}, // 75 == `jne`
    {"Reactor-Class-Mod", {"75 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D D0"}}, // 75 == `jne`
    {"Reactor-Count-Mod", {"7E ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D D0"}}, // 7E == `jle`
    {"Shield-Count-Mod", {"7E ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D 58"}}, // 7E == `jle`
    {"Weapon-Power-Mod", {"EB ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D 30", "7E ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D 58"}}, // EB == `jmp`. This one's unique as the 74 (`je`) 4 ops before (-11 bytes) this to EB (`jmp`).
};

void DoInjection() {
    LOG(TARGET_NAME << " loading.");

    constexpr auto targetVersion = CURRENT_RELEASE_RUNTIME;
    const auto     gameVersion   = GetGameVersion();
    LOG("Target version: " << LOG_VERSION(targetVersion));
    LOG("Game version: " << LOG_VERSION(gameVersion));
    if (targetVersion != gameVersion) {
        LOG("WARNING: TARGET VERSION DOES NOT MATCH DETECTED GAME VERSION! Patching may or may not work.");
        LOG("If you're deliberately running this on an older release expect zero support and do not open bug reports about it not working.");
    }

    const auto moduleName = GetExeFilename();
    const auto moduleAddr = reinterpret_cast<const UINT64>(GetModuleHandle(moduleName.c_str()));
    LOG("Found module name: " << moduleName);
    LOG("Module base address: " << std::uppercase << std::hex << moduleAddr);

    const auto newBytes     = StringToByteVector("EB"); // EB == `jmp`
    auto       patchedCount = 0;

    for (const auto& pattern : SCAN_MAPPING.at(TARGET_NAME)) {
        LOG("Doing AoB scan.");

        auto addressesFound = ScanMemory(moduleName, pattern);
        if (addressesFound.empty()) {
            LOG("AoB scan returned no results, aborting.");
            return;
        }

        LOG("Found " << addressesFound.size() << " match(es).");

        auto validTypes = TYPE_MAPPING.at(TARGET_NAME);

        for (const auto& address : addressesFound) {
            const auto addrBase     = reinterpret_cast<const UINT64>(address);
            const auto moduleOffset = addrBase - moduleAddr;

            // Find the start of the `lea`.
            const auto leaAddress = ScanMemory(moduleName, LEA_START, false, true, address)[0]; // AoBs differ, so scan for the `lea` from the AoB start address.
            const auto leaBase    = reinterpret_cast<const UINT64>(leaAddress);
            //LOG("`lea` found at: +" << std::uppercase << std::hex << reinterpret_cast<const UINT64>(leaAddress) - moduleAddr);
            const auto leaOffset = *reinterpret_cast<const UINT32*>(leaAddress + 3); // In short, move the ptr 3 bytes, and dereference the 4 bytes (the `lea` offset) as an int. // NOLINT(clang-diagnostic-cast-qual)

            const UINT64 strBegin = leaBase + leaOffset + 8; // +7 to offset to the end of the `lea` op, +1 to skip the char count. They're null-terminated anyways.
            const auto   typeStr  = std::string(reinterpret_cast<const char*>(strBegin)); // NOLINT(performance-no-int-to-ptr)
            //LOG("Found string: " << typeStr);

            if (Contains(validTypes, typeStr)) {
                LOG("Target address: " << std::uppercase << std::hex << addrBase << " (" << moduleName << " + " << moduleOffset << ")");
                //PrintNBytes(address, 13);
                //LOG("LEA offset: " << std::uppercase << std::hex << leaOffset);
                //LOG("String addr: " << std::uppercase << std::hex << strBegin);
                //LOG("Type string: " << typeStr);

                if (std::strcmp(TARGET_NAME, "Weapon-Power-Mod") == 0 && typeStr == "SB_LIMITBODY_EXCESS_POWER_WEAPON") {
                    auto jeAddress = address - 11;

                    if (*jeAddress != 0x74) {
                        LOG("Error finding `JE` for `Weapon-Power-Mod`. Expected `74`, found `" << std::uppercase << std::hex << *jeAddress << "`. Aborting.");
                        continue;
                    }

                    LOG("JE offset (-11) address: " << std::uppercase << std::hex << reinterpret_cast<const UINT64>(jeAddress));

                    DoWithProtect(const_cast<BYTE*>(jeAddress), 1, [newBytes, jeAddress] {
                        memcpy(const_cast<BYTE*>(jeAddress), newBytes.data(), newBytes.size());
                    });
                } else {
                    DoWithProtect(const_cast<BYTE*>(address), 1, [newBytes, address] {
                        memcpy(const_cast<BYTE*>(address), newBytes.data(), newBytes.size());
                    });
                }

                LOG(typeStr << " patched.");
                patchedCount++;
            }
        }
    }

    LOG("Patched " << patchedCount << " match(es).");
}

BOOL WINAPI DllMain(HINSTANCE hInst, const DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Do nothing if not an ASI as SFSE will handle it instead.
        if (!EndsWith(GetFullModulePath(), ".asi")) return TRUE;

        SetupLog(GetLogPathAsCurrentDllDotLog());

        LOG(TARGET_NAME << " initializing.");

        auto thread = std::thread([] {
            DoInjection();
        });
        if (thread.joinable()) thread.detach();

        LOG("Scan thread spawned.");
    }
    return TRUE;
}

extern "C" {
// Copied from `PluginAPI.h`.
// ReSharper disable once CppInconsistentNaming
__declspec(dllexport) SFSEPluginVersionData SFSEPlugin_Version = {
    SFSEPluginVersionData::kVersion,

    1,
    TARGET_NAME,
    "LordGregory",

    0, // not address independent
    0, // not structure independent
    {CURRENT_RELEASE_RUNTIME, 0}, // compatible with 1.13.61 and that's it

    0, // works with any version of the script extender. you probably do not need to put anything here
    0, 0, // set these reserved fields to 0
};

// ReSharper disable once CppInconsistentNaming
// ReSharper disable once CppParameterNeverUsed
__declspec(dllexport) bool SFSEPlugin_Load(const SFSEInterface* sfse) {
    SetupLog(GetLogPathAsCurrentDllDotLog());

    LOG(TARGET_NAME << " initializing.");

    auto thread = std::thread([] {
        DoInjection();
    });
    if (thread.joinable()) thread.detach();

    LOG("Scan thread spawned.");
    return true;
}
};