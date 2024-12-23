import openai

from .constants import PROMPT_COMPARE_SIMILARITY, SYSTEM_PROMPT


class LLMHandler:
    def __init__(self, ip_port: str):
        """
        Initializes the LLMHandler instance. If an IP and port are provided,
        initializes the LLM client with the given base URL.
        """
        self.LLM = None
        if ip_port:
            self.init_LLM(ip_port)

    def init_LLM(self, ip_port: str):
        """
        Initializes the LLM client with a specified IP and port.
        """
        self.LLM = openai.OpenAI(
            base_url=f"http://{ip_port}/v1",
            api_key="sk-no-key-required",
        )

    def classification_text_generation(self, content, prompt: str) -> str:

        user_prompt = f"""
        {content}
        {prompt}
        """

        if not self.LLM:
            raise Exception("LLM is not initialized. Please call `init_LLM` first.")

        out = self.LLM.chat.completions.create(
            model="llama-3-70b-q6",
            messages=[
                {"role": "system", "content": f"{SYSTEM_PROMPT}"},
                {"role": "user", "content": f"{user_prompt}"},
            ],
            max_tokens=None,
        )

        return str(out.choices[0].message.content) if out else ""

    def classification_code_similarity(self, script1, script2):
        """
        This function just prepare the prompt and call the classification_text_generation function. It is used to compare two scripts to see if they are similar.
        """

        user_prompt = f"""
        Script 1:
        {script1}

        =====

        Script 2:
        {script2}
        """

        return self.classification_text_generation(
            PROMPT_COMPARE_SIMILARITY, user_prompt
        )
