""" File that contains flashcards' backend """
import json
import os
from dataclasses import asdict, dataclass
from typing import Optional
from dotenv import find_dotenv, load_dotenv
from langchain_openai import ChatOpenAI
from langchain.output_parsers import ResponseSchema, StructuredOutputParser
from langchain.prompts import ChatPromptTemplate
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain_community.utilities.dalle_image_generator import DallEAPIWrapper
from openai import OpenAI
from pydantic import BaseModel, TypeAdapter, parse_obj_as

class Flashcard(BaseModel):
    input_expression: str
    input_language: str
    output_expression: str
    output_language: str
    example_usage_input_language: str
    example_usage_output_language: str
    image_url: Optional[str] = None

class Flashcards(BaseModel):
    data: list[Flashcard]

    def as_json(self) -> dict:
        """
        Converts the collection of Flashcard instances to a JSON format.
        """
        return {"flashcards": [card.model_dump() for card in self.data]}

    @classmethod
    def import_from_json(cls, data: dict) -> "Flashcards":
        """
        Creates a Flashcards instance from a JSON representation.
        """
        flashcard_objects = TypeAdapter.validate_python(list[Flashcard], data["flashcards"])
        return cls(data=flashcard_objects)

    def __len__(self) -> int:
        """
        Returns the number of Flashcard instances in the collection.
        """
        return len(self.data)


class FlashcardGeneratorOpenAI: # pylint: disable=R0903
    """
    A class to generate language learning flashcards using OpenAI's language model.

    Attributes:
        chat (ChatOpenAI): An instance of ChatOpenAI for generating flashcards.
        response_schemas (list): A list of ResponseSchema objects for structuring the response.
        output_parser (StructuredOutputParser): Parser to structure the output
                                                from the language model.
        flashcard_generator_template (str): A template for generating flashcard data.
        prompt (ChatPromptTemplate): A prompt template for the language model.
    """

    def __init__(self, api_key: str, llm_model: str = "gpt-3.5-turbo") -> None:
        """
        Initializes the FlashcardGeneratorOpenAI class with
        the specified API key and language model.

        Args:
            api_key (str): The API key for OpenAI.
            llm_model (str): The name of the language model to use.
        """
        self.chat = ChatOpenAI(temperature=0.0, model=llm_model, api_key=api_key)
        self.image_gen = OpenAI(api_key=api_key)

        input_expression_schema = ResponseSchema(
            name="input_expression",
            type="str",
            description="Original expression entered by the user, refined"
            " to create translated_expression.",
        )
        input_language_schema = ResponseSchema(
            name="input_language",
            type="str",
            description="Language of the input expression.",
        )
        example_usage_input_language_schema = ResponseSchema(
            name="example_usage_input_language",
            type="str",
            description="Example usage of input expression, used to give the user some "
            "example context where it could be used. Limited to one sentence.",
        )
        output_expression_schema = ResponseSchema(
            name="output_expression",
            type="str",
            description="Translation of refined expression entered by the user.",
        )
        output_language_schema = ResponseSchema(
            name="output_language",
            type="str",
            description="Language of the output expression.",
        )
        example_usage_output_language_schema = ResponseSchema(
            name="example_usage_output_language",
            type="str",
            description="Example usage of input expression, used to give the user some "
            "example context where it could be used. Limited to one sentence.",
        )

        response_schemas = [
            input_expression_schema,
            input_language_schema,
            example_usage_input_language_schema,
            output_expression_schema,
            output_language_schema,
            example_usage_output_language_schema,
        ]

        self.output_parser = StructuredOutputParser.from_response_schemas(
            response_schemas
        )
        self.format_instructions = self.output_parser.get_format_instructions()

        self.flashcard_generator_template = """\
        For the following expression, extract the following information:

        input_expression: Original expression entered by the user, but refined to create translated_expression (for flashcard for language learning). If the expression is too long (more than 10 words), it should be shortened while keeping the sense.

        input_language: Language of the input expression

        output_expression: Refined input expression translated to {output_language} language. Provide 2 alternatives, separated with 'slash' sign (and space before & after the sign)

        example_usage_input_language: Example usage of input expression, used to give the user some example context where it could be used. Limited to one sentence. Written in input_language
        
        example_usage_output_language: Same as example_usage_input_language but written in output_language

        input_expression: {input_expression}
        input_language: {input_language}

        {format_instructions}
        """

        self.prompt = ChatPromptTemplate.from_template(
            template=self.flashcard_generator_template
        )

    def generate_flashcard_image(self, expression: str) -> str:
        """
        Generates an image representation of the input expression using the DALL-E model.

        Args:
            expression (str): The expression to be used for generating the image.
        
        Returns:
            str: URL of the generated image.
        """
        response = self.image_gen.images.generate(
            model="dall-e-3",
            prompt=f"""
            Create a visually engaging and educational image to be used on a flashcard, 
            capturing the essence of the given expression in a straightforward and non-extravagant manner. 
            The image should be easily identifiable and closely related to the expression, 
            facilitating quick comprehension. The generated image shall not contain any text. 
            If the expression contains elements that might not align with content guidelines, 
            creatively adapt the concept to ensure it complies while maintaining a clear 
            connection to the original meaning. 
            This adaptation should be subtle, employing visual metaphors or related symbols 
            to convey the expression's essence without explicit or potentially sensitive content.
            Expression: {expression}
            """,
            size="1792x1024",
            quality="standard",
            n=1,
        )
        return response.data[0].url

    def generate_flashcard(
        self, input_exp: str, input_lang: str, output_lang: str
    ) -> Flashcard:
        """
        Generates a flashcard by translating an input expression from one language to another.

        This method takes an expression in a specified input language, translates it into
        a specified output language, and then creates a flashcard containing both the original
        and translated expressions. It uses the ChatOpenAI model to generate the translation
        and example usage.

        Args:
            input_expression (str): The expression to be translated.
            input_language (str): The language of the input expression.
            output_language (str): The language into which the input expression is to be translated.

        Returns:
            Flashcard: An instance of the Flashcard class containing the original expression,
                    its translation, and an example usage in the output language.
        """
        messages = self.prompt.format_messages(
            input_expression=input_exp,
            input_language=input_lang,
            output_language=output_lang,
            format_instructions=self.format_instructions,
        )
        response = self.chat.invoke(messages)
        flashcard_dict = self.output_parser.parse(response.content)
        return Flashcard(**flashcard_dict)


def main():
    """
    For debugging purposes only
    """
    _ = load_dotenv(find_dotenv())  # Read local .env file

    generator = FlashcardGeneratorOpenAI(api_key=os.environ["OPENAI_API_KEY"])

    input_expressions = [
        # "cruel",
        # "let someone off the hook",
        # "it absorbed me",
        # "get my thoughts in order",
        # "crude",
        "pore over",
    ]
    input_language = "English"
    output_language = "Polish"

    flashcards = Flashcards(data=[])

    for input_expression in input_expressions:
        flashcard = generator.generate_flashcard(
            input_expression, input_language, output_language
        )
        # flashcard.image_url = generator.generate_flashcard_image(input_expression)
        print(flashcard)
        flashcards.data.append(flashcard)

if __name__ == "__main__":
    main()
