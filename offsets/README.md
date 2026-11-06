# offsets/

当前构建核对过的偏移表。构建号 `6aebc4da` / `Offsets_Date=2026-11-06`，全是 RVA。

| 文件 | 用途 |
|---|---|
| `deliver.ofs` | 纯文本偏移表，`Key = 0x值;` 一行一条，带 `//` 注释 |
| `deliver.hpp` | C++ 头，`#include` 后直接用 `Offsets::dwEntityList` |
| `deliver.json` | JSON，`json.load()` 后键名就是偏移名 |

三个文件的值完全一致，都是引擎类型表与活内存核对出来的真值；格式不同只是为了
方便不同语言取用。`deliver.ofs` 也只是同一种文本格式，没有额外的语义层。

## 两个字段容易看错

- `m_vecOrigin = 0x80`：这是 `CGameSceneNode::m_vecOrigin`，存的是**局部坐标**。
  世界坐标在 `m_vecAbsOrigin`，偏移 `0xC8`。读玩家世界位置时用后者，别拿
  `0x80` 去当世界坐标用。
- `dwGameTypes = 0x1E2740`：在 `matchmaking.dll` 不在 `client.dll`。
  `Offsets_Date` 那几行里有注释说明哪些键属于哪个模块。

## 换游戏构建后

所有偏移都会变。重新跑一次扫描器生成新表（见根目录 `怎么用.md`），别手改这份。
`legacy/` 里是更早期的静态样本，不要和这里的当前值混用。
