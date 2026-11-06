// 由 cs2re.auto 自动生成，请勿手改。
// client.dll 版本戳 6ae91e98
// 全部为 RVA，使用时加模块基址。
#pragma once
#include <cstdint>

namespace cs2 {

constexpr std::uintptr_t dwViewMatrix             = 0x256F250;
constexpr std::uintptr_t dwViewAngles             = 0x256F188;
constexpr std::uintptr_t dwEntityList             = 0x271EBA8;
constexpr std::uintptr_t dwLocalPlayerController  = 0x2541538;
constexpr std::uintptr_t dwLocalPlayerPawn        = 0x2569948;

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
