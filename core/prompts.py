PROMPTS = {
    "system": "You are a helpful, respectful and honest assistant with a deep knowledge of code and software analysis. Always answer as helpfully as possible, while being safe. Your answers should not include any harmful, unethical, racist, sexist, toxic, dangerous, or illegal content. Please ensure that your responses are socially unbiased and positive in nature. If a question does not make any sense, or is not factually coherent, explain why instead of answering something not correct. If you don't know the answer to a question, please don't share false information.",

    "zero_shot": [
"""You will be provided with two {code_type} snippets which are extracted from two stripped binaries with different compilation settings (i.e., architecture, compiler, optimization), namely Code A and Code B. Your task is to determine whether the two code snippets are compiled from the same source code. The binaries are stripped so that you can not determine the result based on the different variable names (e.g., v1, v2) and function call names (e.g., sub_893B4).
You answer should return as in the following format: 
<same_source>yes or no</same_source>
<explanation>explanation no more than 150 words</explanation>

Code A: {code_A} 

Code B: {code_B}"""
    ],
    "few_shot":[
"DBs/few_shot_examples.json",
"""You will be provided with two {code_type} snippets which are extracted from two stripped binaries with different compilation settings (i.e., architecture, compiler, optimization), namely Code A and Code B. Your task is to determine whether the two code snippets are compiled from the same source code. The binaries are stripped so that you can not determine the result based on the different variable names (e.g., v1, v2) and function call names (e.g., sub_893B4).
You answer should return as in the following format: 
<same_source>yes or no</same_source>
<explanation>explanation no more than 150 words</explanation>

Code A: {code_A} 

Code B: {code_B}"""
    ],
    "cot-lite": [
"""You will be provided with two {code_type} snippets which are extracted from two stripped binaries with different compilation settings (i.e., architecture, compiler, optimization), namely Code A and Code B. The binaries are stripped, so that the variable and function names will be replaced with temporary values without any meanings (e.g., v11, sub_xxx). Your task at first is to generate one sentence to describe the function of two code and then answer the following questions, keep your response concise. 
Questions:
1. What are the constraints in these two functions?
2. Does the two functions have any same additional dependencies or external requirements?
3. Do they share any same constants (i.e., numeric or string literal)?
4. Do they have similar program logic, control dependencies, or data dependencies?

Code A: {code_A} 

Code B: {code_B}""",
"""Let's integrate the above information and determine whether the two functions are compiled from the same source code. You answer should return as in the following format: 
<same_source>yes or no</same_source>
<explanation>explanation no more than 150 words</explanation>"""
    ],
    "cot-pro": [
"""You will be provided with two {code_type} snippets which are extracted from two stripped binaries with different compilation settings (i.e., architecture, compiler, optimization), namely Code A and Code B. The interference of different compilation settings and binary strip are listed as follows:
1. Different compilation settings may introduce variations (e.g., loop unrolling, inlining, dead code elimination), code may replaced by another with the same meaning(e.g., for loop to while loop, if else to switch case). Thus, you should focus on the part that remain consistent across compilation settings (e.g., the initialization, end condition of a loop, the constraints in if/else and cases).
2. Binary strip will remove the symbols of function calls and variables so that you should ignore the temporary name (e.g., v1, sub_xxx) and focus on their roles and relationships (i.e., how are they defined and used).

Your task at first is to generate one sentence to describe the purpose of two code snippets and then answer the following questions, keep your response concise. 

Questions:
From lexical perspective:
1. Do the two code snippets share the same constants, such as mathematical or constraint numeric constant (e.g., v1 &= 0x10, if (a > 10)), string literals (e.g., "hello world")?
2. Do the two code snippets depend on the same external functions (e.g., printf, malloc, strlen) with consistent arguments?
3. Do the two functions accept similar parameters and return the same values and types?   
From semantic perspective:
1. Are the control flow and data flow semantically equivalent?
2. Do the two code snippets perform the same logical operations and semantic patterns, such as mathematical computation, string manipulation and error handling?
3. Does the similar code of two functions executed under the same constrains (e.g., a = 0 when b > 1 and c < 5)?

Code A: {code_A} 

Code B: {code_B}
""",
"""Let's integrate the above information and determine whether the two code snippets are compiled from the same source code. You answer should return as in the following format: 
<same_source>yes or no</same_source>
<explanation>explanation no more than 150 words</explanation>"""
    ],
    "cot-self": [
"""What could be different and the same when the source code is compiled using different compilation settings (i.e., architecture, compiler, optimization) after binary stripped? What should we focus on when determine whether the two {code_type} code snippets extracted from the two stripped binaries with different compilation settings are compiled from the same source code? Keep your response concise (no more than 300 words).""",
"""Let's integrate the above information and finish the task. You will be provided with two {code_type} snippets which are extracted from two stripped binaries with different compilation settings (i.e., architecture, compiler, optimization), namely Code A and Code B. Your task is to determine whether the two code snippets are compiled from the same source code. 
You answer should return as in the following format: 
<same_source>yes or no</same_source>
<explanation>explanation no more than 150 words</explanation>

Code A: {code_A} 

Code B: {code_B}"""

    ],
    "critique": [
"""You will be provided with two {code_type} snippets which are extracted from binaries with different compilation settings (i.e., architecture, compiler, optimization), namely Code A and Code B. The binaries are stripped, so that the variable and function names will be replaced with temporary values without any meanings (e.g., v11, sub_xxx). Your task is to determine whether the two code snippets are compiled from the same source code. 
You answer should return as in the following format: 
<same_source>yes or no</same_source>
<explanation>explanation no more than 150 words</explanation>

Code A: {code_A} 

Code B: {code_B}""",
"Examine your previous response and assess any potential issues. If you find none, simply return <no problem>",
"""Adjust your response in light of the problems you discovered. You answer should return as in the following format: 
<same_source>yes or no</same_source>
<explanation>explanation no more than 150 words</explanation>"""
],
}
