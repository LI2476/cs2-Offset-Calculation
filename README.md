# cs2-Offset-Calculation

给 Counter-Strike 2 找内存偏移的工具，附带一份已经核对过的偏移表。

游戏每次更新，DLL 里各个数据的位置就会挪动。写外部工具的人得重新找一遍这些位置，
手动找又慢又容易错。这个仓库做的事是：把 `client.dll` 拆开看，配合正在运行的游戏
进程，把偏移自动算出来，再逐条验证一遍。

## 偏移是什么

一句话：偏移就是某个数据在一大块内存里的「门牌号」。DLL 加载到内存后有个起始
地址（基址），基址加上偏移，才是数据的真实地址。基址每次开机都可能变，偏移在同
一次游戏构建里是固定的，所以工具输出的是偏移（RVA，相对虚拟地址），用的时候
自己加上当时的模块基址。

举个例子：`dwEntityList = 0x271FBB8` 的意思是「实体列表的入口，在 client.dll
基址往后 0x271FBB8 字节处」。

## 仓库里有什么

| 目录 | 内容 |
|---|---|
| `cs2re/` | 扫描器本体，一个 Python 包 |
| `verify_all39.py`、`verify_live.py` | 两条验证器，把算出来的偏移拿去核对 |
| `offsets/` | 当前构建（build `6aebc4da`，2026-11-06）核对过的偏移表 |
| `legacy/` | 更早期的静态偏移样本，别和 `offsets/` 混用 |
| `怎么用.md` | 使用说明，含三种模式和故障排查 |
| `一键扫描.bat` | Windows 下双击运行 |

依赖见 `requirements.txt`，用法见 `怎么用.md`。

## 当前偏移表

`offsets/deliver.ofs` 是主产物，7 个 `dw*` 全局变量加 58 个 `m_*` 字段，都是 RVA。
同一份数据的另外两种格式 `deliver.hpp`（C++ 头）和 `deliver.json` 值完全一致。
几个关键值：

| 名称 | 值 | 说明 |
|---|---|---|
| `dwLocalPlayerController` | `0x2542548` | 本地玩家本人（controller） |
| `dwLocalPlayerPawn` | `0x223F4C8` | 当前操纵的角色（pawn） |
| `dwEntityList` | `0x271FBB8` | 实体列表入口 |
| `dwViewAngles` | `0x2570188` | 视角角度 |
| `dwViewMatrix` | `0x2570250` | 视图矩阵 |
| `dwGameTypes` | `0x1E2740` | 在 matchmaking.dll 里，不在 client.dll |
| `dwSensitivity` | `0x2567C48` | 鼠标灵敏度 |

两个字段容易看错：

- `m_vecOrigin = 0x80` 是 `CGameSceneNode` 的**局部坐标**。世界坐标在
  `m_vecAbsOrigin`，偏移 `0xC8`。想拿玩家在世界里的位置，读后者。
- `dwGameTypes` 属于 `matchmaking.dll`，算基址时别拿 client.dll 的基址去加。

## 两个容易踩的坑

**PID 会被系统回收。** 进程编号关掉后可能分给别的程序。工具在连接前会核对进程名
是不是 cs2.exe，不是就拒绝，避免连到一个无关的进程、读出一堆垃圾还当成结果。

**同一帧里视角角度有好几份副本。** 曾经有 7 个候选位置的数值在同一帧完全一致，
连采 25 次都分不出真假。光看「数值对不对」不够，还得看代码有没有真的引用这个
位置、指针链能不能闭合。工具把动态证据和静态证据分开打分，动态证据弱的候选不会
因为静态分高就混进来。

更多踩坑记录和判据强度排序写在 `怎么用.md` 里。

## 已知限制

- `dwLocalPlayerPawn` 在代码里没有直接的 RIP 引用，离线模式下靠签名库定案，
  证据比别的项弱一档。
- `dwPlantedC4` 还没接进验证器。
- 复合字段（几段偏移拼起来）依赖 `schema.ALIASES` 里的人工映射。
- 第一次建 schema 缓存要约 70 秒，之后是 0.02 秒；缓存按 DLL 的三个指纹校验，
  游戏更新会自动重建。

## 快速开始

```bash
pip install -r requirements.txt
python -m cs2re.auto --dll "<Steam 库>\Counter-Strike Global Offensive\game\cs2\bin\win64\client.dll"
```

不带 `--dll` 时读取环境变量 `CS2RE_DLL`。Windows 下也可以直接双击
`一键扫描.bat`。三种模式（离线 / 实时 / 只验证）和故障排查见 `怎么用.md`。

## 许可证

未指定。若要开源发布，自己挑一个 LICENSE 放进根目录。
