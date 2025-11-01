import time
from loguru import logger
from openai import OpenAI, BadRequestError, PermissionDeniedError, RateLimitError, NotGiven, APIError
from core.prompts import PROMPTS
from httpx import ReadTimeout

NOT_GIVEN = NotGiven()


class LLM(object):
    def __init__(self, base_url, model_name, api_key, **kwargs):
        self.base_url = base_url
        self.model_name = model_name
        self.client = OpenAI(api_key=api_key, base_url=base_url, default_headers=kwargs.get('default_headers', None))
        self.top_p = kwargs.get('top_p', NOT_GIVEN)
        self.temperature = kwargs.get('temperature', NOT_GIVEN)
        self.max_tokens = kwargs.get('max_tokens', NOT_GIVEN)
        self.use_system = kwargs.get('use_system', True)

    def _ask(self, content, history=[]):
        if self.use_system:
            messages = [{"role": "system", "content": PROMPTS['system']}]
        else:
            messages = []
        for q, a in history:
            messages.append({"role": "user", "content": q})
            messages.append({"role": "assistant", "content": a})

        messages.append({"role": "user", "content": content})

        response = self.client.chat.completions.create(
            model=self.model_name, messages=messages, stream=True,
            temperature=self.temperature,
            top_p=self.top_p,
            max_completion_tokens=self.max_tokens,
            timeout=600,
        )
        reason_resp = ""
        resp = ""
        for chunk in response:
            try:
                tmp_resp = chunk.choices[0].delta.content
            except IndexError:
                continue
            except AttributeError:
                continue
            else:
                if tmp_resp is not None:
                    resp += tmp_resp
            try:
                tmp_reason_resp = chunk.choices[0].delta.reasoning_content
            except AttributeError:
                continue
            else:
                if tmp_reason_resp is not None:
                    reason_resp += tmp_reason_resp
        if reason_resp:
            result = reason_resp + "</think>" + resp
        else:
            result = resp
        return result

    def ask(self, content, history=[]):
        retry_num = 1
        time_sleep = 0
        sleep_unit = 65
        while True:
            try:
                output = self._ask(content, history)
            except RateLimitError as e:
                if "Request too large for" in e.message:
                    logger.error(e)
                    output = str(e)
                    break
                logger.error(f"Rate Limit Exceeded! Wait for 65 seconds (retry num: {retry_num}, time sleep: {time_sleep + sleep_unit})")
                time.sleep(sleep_unit)
                time_sleep += sleep_unit
                retry_num += 1
            except ReadTimeout as e:
                output = str(e)
                break
            except BadRequestError as e:
                logger.error(f"Bad Request! Too long content. {e}")
                output = str(e)
                break
            except APIError as e:
                logger.error(f"API Error! Too long content. {e}")
                output = str(e)
                break
            else:
                break
        if "</think>" in output:
            think, *output = output.split("</think>")
            output = "</think>".join(output)
        else:
            think = None
        return {
            'output': output,
            'think': think,
            'time_sleep': time_sleep,
        }


