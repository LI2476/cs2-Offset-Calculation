// 由 cs2re.auto 自动生成，请勿手改。
// client.dll 版本戳 6aebc4da
// 全部为 RVA，使用时加模块基址。
#pragma once
#include <cstdint>

namespace cs2 {

constexpr std::uintptr_t dwViewMatrix             = 0x2570250;
constexpr std::uintptr_t dwViewAngles             = 0x2570188;
constexpr std::uintptr_t dwEntityList             = 0x271FBB8;
constexpr std::uintptr_t dwLocalPlayerController  = 0x2542548;
constexpr std::uintptr_t dwLocalPlayerPawn        = 0x223F4C8;
constexpr std::uintptr_t dwSensitivity            = 0x2567C48;
constexpr std::uintptr_t dwGameTypes              = 0x1E2740;

}  // namespace cs2

/*  用法：
    std::uintptr_t base = (std::uintptr_t)
        GetModuleHandleA("client.dll");

    // 视角（两个 float：pitch, yaw）
    float* angles = (float*)(base + cs2::dwViewAngles);

    // 视图矩阵（4x4 float，行优先）
    float* matrix = (float*)(base + cs2::dwViewMatrix);

    // 实体列表（指针链：list -> chunk -> entity）
    std::uintptr_t list = *(std::uintptr_t*)(base + cs2::dwEntityList);

    // 本地玩家控制器 / 本体
    std::uintptr_t ctrl = *(std::uintptr_t*)
        (base + cs2::dwLocalPlayerController);
    std::uintptr_t pawn = *(std::uintptr_t*)
        (base + cs2::dwLocalPlayerPawn);
*/
