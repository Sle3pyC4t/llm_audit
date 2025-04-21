"""
Tool Center for LLM Audit

Provides tools for:
- Knowledge base connection
- Report generation
- System tool calls
- Internet access
"""

import os
import logging
import subprocess
import re
from typing import Dict, List, Optional, Any

import requests
from langchain.tools import Tool
from langchain_core.tools import BaseTool

from ..config import Config

logger = logging.getLogger(__name__)


class ToolCenter:
    """Provides a central repository of tools available to agents"""
    
    def __init__(self, config: Config):
        self.config = config
        self.tools: Dict[str, BaseTool] = {}
        self._initialize_tools()
        
    def _initialize_tools(self):
        """Initialize all available tools"""
        # File system tools
        self.tools["read_file"] = Tool(
            name="read_file",
            func=self.read_file,
            description="Read the contents of a file from the codebase being audited"
        )
        
        self.tools["list_directory"] = Tool(
            name="list_directory",
            func=self.list_directory,
            description="List the contents of a directory in the codebase being audited"
        )
        
        # Knowledge base tools
        self.tools["search_knowledge_base"] = Tool(
            name="search_knowledge_base",
            func=self.search_knowledge_base,
            description="Search the knowledge base for information about security vulnerabilities"
        )
        
        # Report tools
        self.tools["add_to_report"] = Tool(
            name="add_to_report",
            func=self.add_to_report,
            description="Add information to the audit report"
        )
        
        # System tools
        self.tools["run_command"] = Tool(
            name="run_command",
            func=self.run_command,
            description="Run a shell command and return the output"
        )
        
        # Internet tools
        self.tools["web_search"] = Tool(
            name="web_search",
            func=self.web_search,
            description="Search the web for information"
        )
        
    def get_tools(self, tool_names: Optional[List[str]] = None) -> List[BaseTool]:
        """Get a list of tools by name
        
        Args:
            tool_names: Optional list of tool names to retrieve. If None, all tools are returned.
            
        Returns:
            List of tools
        """
        if tool_names is None:
            return list(self.tools.values())
        
        return [self.tools[name] for name in tool_names if name in self.tools]
    
    # File system tools
    def read_file(self, file_path: str) -> str:
        """Read the contents of a file
        
        Args:
            file_path: Path to the file, relative to the codebase root
            
        Returns:
            Contents of the file
        """
        full_path = os.path.join(self.config.codebase_path, file_path)
        
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading file {full_path}: {str(e)}")
            return f"Error reading file: {str(e)}"
    
    def list_directory(self, dir_path: str) -> List[str]:
        """List the contents of a directory
        
        Args:
            dir_path: Path to the directory, relative to the codebase root
            
        Returns:
            List of files and directories
        """
        full_path = os.path.join(self.config.codebase_path, dir_path)
        
        try:
            return os.listdir(full_path)
        except Exception as e:
            logger.error(f"Error listing directory {full_path}: {str(e)}")
            return [f"Error listing directory: {str(e)}"]
    
    # 从中文关键词映射到相关文件，由于文件名是英文的
    def _get_chinese_to_english_mappings(self):
        """获取中英文关键词映射关系
        
        Returns:
            两个字典：中文到英文的映射，以及中文关键词到相关文件的映射
        """
        # 中文关键词到英文的映射
        cn_to_en = {
            "清算": "liquidation",
            "贷款": "lending",
            "借贷": "lending",
            "抵押品": "collateral",
            "债务": "debt",
            "漏洞": "vulnerability",
            "智能合约": "smart contract",
            "合约": "contract",
            "滑点": "slippage",
            "去中心化交易所": "dex",
            "交易所": "exchange",
            "安全": "security",
            "攻击": "attack",
            "审计": "audit",
            "风险": "risk",
            "dao": "dao",
            "治理": "governance",
            "投票": "voting",
            "签名": "signature",
            "重放": "replay",
            "预言机": "oracle"
        }
        
        # 中文关键词到相关文件的映射
        cn_keyword_to_files = {
            "清算": ["liquidation.md", "lending.md"],
            "借贷": ["lending.md", "liquidation.md"],
            "贷款": ["lending.md", "liquidation.md"],
            "滑点": ["slippage.md", "univ3.md"],
            "治理": ["dao.md"],
            "投票": ["dao.md"],
            "签名": ["signaturereplay.md"],
            "重放": ["signaturereplay.md"],
            "内联": ["inlineassembly.md"],
            "流动性": ["liquiditymanager.md", "univ3.md"],
            "链接": ["chainlink.md"],
            "预言机": ["chainlink.md"]
        }
        
        return cn_to_en, cn_keyword_to_files
        
    def search_knowledge_base(self, query: str) -> str:
        """Search the knowledge base for information
        
        Args:
            query: Search query
            
        Returns:
            Search results
        """
        try:
            logger.info(f"Searching knowledge base for: {query}")
            
            # 确定基础知识库目录
            kb_dir = self.config.knowledge_base_path
            
            # 识别用户可能需要的知识库子目录
            subdirectories = []
            
            # 获取中英文映射关系
            cn_to_en, cn_keyword_to_files = self._get_chinese_to_english_mappings()
            
            # 基于查询关键字自动确定相关子目录
            query_lower = query.lower()
            
            # 检查是否包含中文字符
            has_chinese = any('\u4e00' <= char <= '\u9fff' for char in query)
            
            # 常规英文查询处理
            if "solidity" in query_lower or "smart contract" in query_lower or "blockchain" in query_lower or "defi" in query_lower:
                solidity_dir = os.path.join(kb_dir, "solidity")
                if os.path.exists(solidity_dir):
                    subdirectories.append(solidity_dir)
            
            # 中文查询优化
            if has_chinese:
                # 对于包含中文的查询，直接添加solidity目录（大多数中文查询会寻找solidity相关内容）
                solidity_dir = os.path.join(kb_dir, "solidity")
                if os.path.exists(solidity_dir):
                    subdirectories.append(solidity_dir)
            
            # 如果未指定具体子目录，则包括主目录和solidity子目录(如果存在)
            if not subdirectories:
                subdirectories.append(kb_dir)
                # 默认情况通常是查询solidity相关内容
                solidity_dir = os.path.join(kb_dir, "solidity")
                if os.path.exists(solidity_dir) and os.path.isdir(solidity_dir):
                    subdirectories.append(solidity_dir)
            
            # 检查目录是否存在
            valid_dirs = []
            for dir_path in subdirectories:
                if os.path.exists(dir_path):
                    valid_dirs.append(dir_path)
                else:
                    logger.warning(f"Knowledge base directory not found: {dir_path}")
            
            if not valid_dirs:
                return f"Knowledge base directories not found: {', '.join(subdirectories)}"
            
            # 收集所有markdown文件
            md_files = []
            target_files = []  # 用于保存中文关键词匹配到的特定文件
            
            # 如果有中文关键词，尝试直接匹配到特定文件
            if has_chinese:
                for cn_keyword, files in cn_keyword_to_files.items():
                    if cn_keyword in query_lower:
                        for file in files:
                            # 在solidity目录查找
                            for dir_path in valid_dirs:
                                if "solidity" in dir_path:
                                    file_path = os.path.join(dir_path, file)
                                    if os.path.exists(file_path):
                                        target_files.append(file_path)
            
            # 如果中文关键词没有匹配到特定文件，则使用普通目录扫描
            if not target_files:
                for dir_path in valid_dirs:
                    for root, _, files in os.walk(dir_path):
                        for file in files:
                            if file.endswith('.md'):
                                md_files.append(os.path.join(root, file))
            else:
                # 使用中文关键词匹配到的文件
                md_files = target_files
            
            if not md_files:
                logger.warning(f"No knowledge base files found in: {', '.join(valid_dirs)}")
                return f"No knowledge base files found in: {', '.join(valid_dirs)}"
            
            # 提取关键词并净化
            # 使用更智能的关键词提取，排除常见的停用词
            stop_words = {"and", "or", "the", "a", "an", "in", "on", "at", "to", "for", "with", "about", "is", "are"}
            keywords = []
            
            # 为中文查询添加英文对应词
            if has_chinese:
                # 提取中文关键词
                cn_keywords = []
                for word in query_lower.split():
                    # 检查是否包含中文字符
                    if any('\u4e00' <= char <= '\u9fff' for char in word):
                        # 去除标点符号
                        word = word.strip(".,;:!?()-，。；：！？（）")
                        if len(word) > 0:
                            cn_keywords.append(word)
                
                # 添加中文关键词对应的英文词
                for cn_word in cn_keywords:
                    if cn_word in cn_to_en:
                        en_word = cn_to_en[cn_word]
                        keywords.append(en_word)
                    keywords.append(cn_word)  # 同时保留中文关键词
                
                # 如果是"清算"相关查询，添加特定的英文关键词
                if any(word in query_lower for word in ["清算", "抵押品", "贷款", "借贷"]):
                    special_keywords = ["liquidation", "collateral", "lending", "loan", "debt", "margin"]
                    keywords.extend(special_keywords)
            
            # 处理普通英文关键词
            for word in query_lower.split():
                # 跳过中文字符
                if any('\u4e00' <= char <= '\u9fff' for char in word):
                    continue
                    
                # 去除标点符号
                word = word.strip(".,;:!?()-")
                # 添加长度大于2的非停用词
                if len(word) > 2 and word not in stop_words:
                    keywords.append(word)
            
            # 确保至少有一个关键词
            if not keywords:
                if has_chinese:
                    # 默认使用常见中英文安全术语
                    keywords = ["vulnerability", "security", "漏洞", "安全", "smart contract", "智能合约"]
                else:
                    keywords = ["vulnerability", "security"]
            
            # 用于跟踪关键词权重的字典
            keyword_weights = {keyword: 1.0 for keyword in keywords}
            
            # 增加特定查询中核心词的权重
            important_terms = ["vulnerability", "attack", "exploit", "issue", "security", "bug", "漏洞", "风险", "攻击", "安全", "智能合约"]
            for term in important_terms:
                if term in keyword_weights:
                    keyword_weights[term] = 2.0  # 更高权重
            
            # 特定领域术语的权重也提高
            if any(term in keyword_weights for term in ["liquidation", "liquidate", "清算"]):
                # 与清算相关的术语
                for term in ["liquidation", "liquidate", "liquidator", "清算"]:
                    if term in keyword_weights:
                        keyword_weights[term] = 3.0  # 更高权重
                # 添加更多相关术语
                related_terms = {
                    "collateral": "抵押品", 
                    "margin": "保证金",
                    "insolvency": "资不抵债",
                    "liquidatable": "可清算",
                    "debt": "债务",
                    "loan": "贷款",
                    "borrowing": "借款",
                    "lending": "借贷"
                }
                for en_term, cn_term in related_terms.items():
                    if en_term not in keyword_weights:
                        keywords.append(en_term)
                        keyword_weights[en_term] = 1.5
                    # 对中文查询添加中文术语
                    if has_chinese and cn_term not in keyword_weights:
                        keywords.append(cn_term)
                        keyword_weights[cn_term] = 1.5
            
            # 添加常见同义词和相关术语
            keyword_expansions = {
                "bug": ["vulnerability", "issue", "exploit", "attack", "flaw"],
                "vulnerability": ["bug", "issue", "exploit", "attack", "flaw", "漏洞"],
                "attack": ["exploit", "vulnerability", "hack", "攻击"],
                "security": ["safety", "protection", "vulnerability", "安全"],
                "contract": ["solidity", "code", "implementation", "合约"],
                "defi": ["finance", "lending", "liquidity", "swap", "金融"],
                "nft": ["token", "erc721", "non-fungible"],
                "dao": ["governance", "voting", "治理"],
                "audit": ["review", "analysis", "assessment", "审计"],
                "liquidation": ["liquidate", "liquidator", "margin", "collateral", "清算"],
                "smart contract": ["solidity", "code", "implementation", "智能合约"],
                # 中文关键词扩展
                "漏洞": ["vulnerability", "bug", "issue", "exploit", "attack"],
                "安全": ["security", "safety", "protection"],
                "智能合约": ["smart contract", "solidity", "code", "contract"],
                "清算": ["liquidation", "liquidate", "liquidator"],
                "抵押品": ["collateral", "asset"],
                "借贷": ["lending", "loan", "debt", "borrow"]
            }
            
            expanded_keywords = keywords.copy()
            for keyword in keywords:
                if keyword in keyword_expansions:
                    expanded_keywords.extend(keyword_expansions[keyword])
            
            # 去重
            expanded_keywords = list(set(expanded_keywords))
            
            if not expanded_keywords:
                # 默认关键词根据查询上下文调整
                if has_chinese:
                    if any(word in query_lower for word in ["清算", "抵押品", "贷款", "借贷"]):
                        expanded_keywords = ["liquidation", "vulnerability", "security", "清算", "漏洞", "抵押品", "贷款"]
                    else:
                        expanded_keywords = ["vulnerability", "security", "漏洞", "安全", "智能合约", "contract"]
                elif "liquidation" in query_lower or "清算" in query_lower:
                    expanded_keywords = ["liquidation", "vulnerability", "security", "清算", "漏洞"]
                else:
                    expanded_keywords = ["vulnerability", "security", "漏洞", "安全"]
            
            # 搜索每个文件的关键词
            results = []
            for md_file in md_files:
                try:
                    with open(md_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # 计算相关性得分
                    file_relevance = 0
                    keyword_matches = {}
                    
                    # 1. 基于关键词计算相关性，考虑权重
                    for keyword in expanded_keywords:
                        count = content.lower().count(keyword)
                        if count > 0:
                            # 应用权重 (如果是原始关键词)
                            weight = keyword_weights.get(keyword, 1.0)
                            weighted_score = count * weight
                            file_relevance += weighted_score
                            # 记录每个关键词的匹配次数，用于后续确定相关段落
                            keyword_matches[keyword] = count
                    
                    # 2. 检测文件名是否包含关键词，若包含则增加分数
                    file_name = os.path.basename(md_file)
                    file_name_lower = file_name.lower().replace('.md', '').replace('_', ' ')
                    for keyword in keywords:  # 只检查原始关键词
                        if keyword in file_name_lower:
                            file_relevance += 10 * keyword_weights.get(keyword, 1.0)  # 文件名匹配权重更高
                    
                    # 3. 对特定查询的特殊处理
                    # 清算相关查询
                    if ("liquidation" in query_lower or "清算" in query_lower) and "liquidation.md" in md_file.lower():
                        file_relevance *= 2.0  # 清算相关查询时，清算专用文件优先级更高
                    
                    # 中文查询的特殊加分
                    if has_chinese and any('\u4e00' <= char <= '\u9fff' for char in content):
                        file_relevance *= 1.5  # 对包含中文内容的文件给予额外加分
                    
                    if file_relevance > 0:
                        # 从文件内容中提取最相关的段落
                        relevant_paragraphs = self._extract_relevant_paragraphs(
                            content, 
                            keywords, 
                            expanded_keywords,
                            max_paragraphs=4  # 增加到4个段落，提供更多上下文
                        )
                        
                        # 增加标题行
                        if relevant_paragraphs:
                            # 查找文件标题
                            title = file_name.replace('.md', '').replace('_', ' ').title()
                            headers = re.findall(r'^\s*#\s+(.+)$', content, re.MULTILINE)
                            if headers:
                                title = headers[0].strip()
                                
                            # 添加到结果
                            results.append({
                                "file_name": file_name,
                                "title": title,
                                "relevance": file_relevance,
                                "paragraphs": relevant_paragraphs,
                                "keyword_matches": keyword_matches
                            })
                except Exception as e:
                    logger.error(f"Error reading knowledge base file {md_file}: {str(e)}")
            
            # 格式化搜索结果为易于阅读的格式
            return self._format_search_results(results, query)
        except Exception as e:
            logger.error(f"Error searching knowledge base: {str(e)}")
            return f"Error searching knowledge base: {str(e)}"
    
    def _extract_relevant_paragraphs(self, content, keywords, expanded_keywords, max_paragraphs=3):
        """从内容中提取最相关的段落
        
        Args:
            content: 文档内容
            keywords: 原始关键词列表
            expanded_keywords: 扩展后的关键词列表
            max_paragraphs: 最大段落数
            
        Returns:
            最相关段落列表
        """
        # 按段落分割内容
        paragraphs = re.split(r'\n\s*\n', content)
        
        # 为每个段落计算相关性得分
        paragraph_scores = []
        for i, paragraph in enumerate(paragraphs):
            score = 0
            # 原始关键词匹配分数更高
            for keyword in keywords:
                score += paragraph.lower().count(keyword) * 3
            
            # 扩展关键词匹配分数较低
            for keyword in expanded_keywords:
                if keyword not in keywords:  # 避免重复计算
                    score += paragraph.lower().count(keyword)
            
            # 标题和小标题段落得分更高
            if re.match(r'^#{1,3}\s+', paragraph):
                score *= 1.5
            
            # 包含编号列表或项目符号的段落得分更高（通常是重要信息）
            if re.search(r'^\s*[\d*-]\s+', paragraph, re.MULTILINE):
                score *= 1.2
                
            # 包含"vulnerability"、"attack"、"exploit"等关键安全术语的段落得分更高
            security_terms = ["vulnerability", "attack", "exploit", "issue", "risk", "threat", "防范建议", "漏洞", "攻击"]
            for term in security_terms:
                if term in paragraph.lower():
                    score *= 1.3
                    break
            
            if score > 0:
                paragraph_scores.append((i, paragraph, score))
        
        # 按分数排序
        paragraph_scores.sort(key=lambda x: x[2], reverse=True)
        
        # 保留得分最高的段落
        top_paragraphs = paragraph_scores[:max_paragraphs]
        
        # 按原始顺序重新排序(保持文档的逻辑流)
        top_paragraphs.sort(key=lambda x: x[0])
        
        # 返回段落文本
        return [p[1] for p in top_paragraphs]
    
    # 格式化搜索结果为易于阅读的格式
    def _format_search_results(self, results, query):
        """格式化搜索结果
        
        Args:
            results: 搜索结果列表
            query: 原始查询
            
        Returns:
            格式化后的结果字符串
        """
        if not results:
            return f"No relevant knowledge base entries found for query: {query}"
            
        # 从结果中筛选出不同的文件（避免重复文件）
        unique_files = {}
        for result in results:
            file_name = result["file_name"]
            if file_name not in unique_files or result["relevance"] > unique_files[file_name]["relevance"]:
                unique_files[file_name] = result
        
        # 按相关性排序
        unique_results = list(unique_files.values())
        unique_results.sort(key=lambda x: x["relevance"], reverse=True)
        
        # 格式化返回结果（最多5个结果）
        formatted_results = []
        for result in unique_results[:5]:
            # 构建标题并包含文件名和相关性得分
            header = f"## {result['title']} (Source: {result['file_name']}, Relevance: {result['relevance']})"
            
            # 添加最相关段落
            paragraphs = "\n\n".join(result["paragraphs"])
            
            # 组装段落
            formatted_results.append(f"{header}\n\n{paragraphs}")
        
        # 如果返回结果太长，则简化为最相关的内容
        combined_results = "\n\n".join(formatted_results)
        if len(combined_results) > 5000:
            # 只保留最相关的2个结果
            combined_results = "\n\n".join(formatted_results[:2])
            
            # 添加摘要信息
            combined_results += f"\n\n_Note: Search returned {len(results)} results. Showing only the most relevant ones. Refine your query for more specific information._"
        
        return combined_results
    
    # Report tools
    def add_to_report(self, section: str, content: str) -> str:
        """Add information to the audit report
        
        Args:
            section: Report section to add to
            content: Content to add
            
        Returns:
            Confirmation message
        """
        # In a real implementation, this would update a report object
        # For now, we'll just log it
        logger.info(f"Adding to report section '{section}': {content[:100]}...")
        return f"Added content to report section: {section}"
    
    # System tools
    def run_command(self, command: str) -> str:
        """Run a shell command and return the output
        
        Args:
            command: Command to run
            
        Returns:
            Command output
        """
        try:
            # Set cwd to the codebase path to run commands relative to it
            result = subprocess.run(
                command,
                shell=True,
                cwd=self.config.codebase_path,
                capture_output=True,
                text=True,
                timeout=30  # Timeout after 30 seconds
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return "Command timed out after 30 seconds"
        except Exception as e:
            logger.error(f"Error running command {command}: {str(e)}")
            return f"Error running command: {str(e)}"
    
    # Internet tools
    def web_search(self, query: str) -> str:
        """Search the web for information
        
        Args:
            query: Search query
            
        Returns:
            Search results
        """
        # In a real implementation, this would use a proper search API
        # For now, we'll just return a placeholder
        return f"Web search results for query: {query}" 