# legacy/

更早期的静态偏移样本，对着旧一版 client.dll 记的：

| 文件 | 内容 |
|---|---|
| `offsets.py` | 一份手写的偏移常量表，按结构分组 |
| `offsets.hpp` | 5 个全局的 C++ `constexpr` |
| `offsets.json` | 一次扫描的打分明细（旧 build `6ae91e98`） |

这些值都比 `offsets/` 里的当前表旧，别拿来用。放着是为了看偏移怎么随版本搬动，
以及当时打分逻辑长什么样。`offsets.json` 里的 dll 路径已换成占位。
