# DNS-FUZZER

一个用Python编写的DNS模糊测试工具，类似于dns-differential-fuzzing项目。该工具专注于DNS查询的模糊测试，支持动态加载变异策略。

## 特性

- **模块化设计**: 核心查询模块与变异策略分离
- **动态策略加载**: 支持运行时加载和配置变异策略
- **丰富的变异策略**: 包含基础、头部和记录级别的变异策略
- **配置文件支持**: 使用YAML格式的配置文件
- **命令行界面**: 提供完整的CLI工具
- **并发支持**: 支持多线程并发请求
- **详细日志**: 可配置的日志级别和输出

## 安装

### 从源码安装

```bash
git clone <repository-url>
cd DNS-FUZZER
pip install -e .
```

### 依赖要求

- Python 3.8+
- dnspython
- click
- pyyaml
- colorama
- tqdm
- dataclasses-json
- typing-extensions

## 快速开始

### 1. 初始化配置文件

```bash
dns-fuzzer init-config
```

这将创建一个默认的`fuzzer_config.yaml`配置文件。

### 2. 查看可用策略

```bash
dns-fuzzer list-strategies
```

### 3. 开始模糊测试

```bash
# 基本用法
dns-fuzzer fuzz -t 8.8.8.8 -n example.com

# 指定多个目标服务器
dns-fuzzer fuzz -t 8.8.8.8 -t 1.1.1.1 -n test.com

# 使用特定策略
dns-fuzzer fuzz -t 8.8.8.8 -s random_query_name -s long_query_name

# 设置迭代次数和并发数
dns-fuzzer fuzz -t 8.8.8.8 -i 1000 --concurrent 20
```

### 4. 测试策略

```bash
# 测试特定策略
dns-fuzzer test-strategy -s random_query_name -c 10

# 测试所有启用的策略
dns-fuzzer test-strategy -n example.com -c 5
```

## 配置文件

配置文件使用YAML格式，包含以下主要部分：

```yaml
# 目标服务器配置
target_servers:
  - "8.8.8.8"
  - "1.1.1.1"
target_port: 53
timeout: 5.0

# 模糊测试配置
max_iterations: 1000
concurrent_requests: 10
delay_between_requests: 0.1

# 策略配置
strategy_selection_mode: "weighted_random"
strategies:
  - name: "random_query_name"
    enabled: true
    weight: 1.0
    parameters: {}
```

## 变异策略

### 基础策略 (Basic Strategies)

- `random_query_name`: 随机查询名称
- `random_query_type`: 随机查询类型
- `random_query_class`: 随机查询类别
- `random_query_id`: 随机查询ID
- `boundary_query_id`: 边界值查询ID
- `long_query_name`: 超长查询名称
- `invalid_character`: 无效字符注入
- `empty_field`: 空字段测试
- `case_variation`: 大小写变化
- `numeric_query_name`: 数字查询名称
- `special_domain`: 特殊域名测试

### 头部策略 (Header Strategies)

- `random_opcode`: 随机操作码
- `random_response_code`: 随机响应码
- `random_flags`: 随机标志位
- `invalid_flag_combination`: 无效标志组合
- `query_as_response`: 查询作为响应
- `response_as_query`: 响应作为查询
- `edns_mutation`: EDNS变异
- `truncated_flag`: 截断标志测试
- `zero_query_id`: 零查询ID

### 记录策略 (Record Strategies)

- `random_record_type`: 随机记录类型
- `invalid_record_data`: 无效记录数据
- `record_ttl_mutation`: TTL变异
- `duplicate_record`: 重复记录
- `empty_record_section`: 空记录段
- `mismatched_record`: 不匹配记录
- `large_record`: 大记录测试
- `record_compression`: 记录压缩
- `wildcard_record`: 通配符记录

## 编程接口

### 基本用法

```python
from dns_fuzzer import DNSQuery, DNSQueryBuilder, DNSMutator
from dns_fuzzer.config import load_config

# 创建基础查询
query = DNSQueryBuilder().name("example.com").qtype("A").build()

# 加载配置
config = load_config()

# 创建变异器
mutator = DNSMutator()

# 应用变异
mutated_query = mutator.mutate_query(query)
```

### 自定义策略

```python
from dns_fuzzer.strategies import BaseMutationStrategy

class CustomStrategy(BaseMutationStrategy):
    def __init__(self):
        super().__init__()
        self.name = "custom_strategy"
        self.description = "Custom mutation strategy"
    
    def can_mutate(self, query: DNSQuery) -> bool:
        return True
    
    def mutate(self, query: DNSQuery) -> DNSQuery:
        # 实现自定义变异逻辑
        mutated = query.clone()
        mutated.name = f"custom-{query.name}"
        return mutated

# 注册策略
mutator.register_strategy(CustomStrategy())
```

## 开发

### 运行测试

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行测试
pytest

# 运行特定测试
pytest tests/test_query.py

# 生成覆盖率报告
pytest --cov=dns_fuzzer
```

### 代码格式化

```bash
# 格式化代码
black src/ tests/

# 检查代码风格
flake8 src/ tests/

# 类型检查
mypy src/
```

## 项目结构

```
DNS-FUZZER/
├── src/
│   └── dns_fuzzer/
│       ├── __init__.py          # 包初始化
│       ├── __main__.py          # 模块入口
│       ├── cli.py               # 命令行界面
│       ├── config.py            # 配置管理
│       ├── core/                # 核心模块
│       │   ├── __init__.py
│       │   ├── query.py         # DNS查询核心
│       │   └── mutator.py       # 变异器核心
│       └── strategies/          # 变异策略
│           ├── __init__.py
│           ├── base.py          # 基础策略类
│           ├── basic.py         # 基础策略
│           ├── header.py        # 头部策略
│           └── record.py        # 记录策略
├── tests/                       # 测试文件
├── fuzzer_config.yaml          # 默认配置
├── pyproject.toml              # 项目配置
└── README.md                   # 项目说明
```

## 许可证

本项目采用MIT许可证。详见LICENSE文件。

## 贡献

欢迎提交Issue和Pull Request！

## 致谢

本项目受到dns-differential-fuzzing项目的启发。