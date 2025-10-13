import io
import json
import logging

import dotenv
import textwrap

from pydantic import BaseModel, Field, RootModel
from llama_index.core.output_parsers import PydanticOutputParser


class AttackFlowItem(BaseModel):
    position: int = Field(description="order of object starting at 0")
    attack_technique_id: str
    name: str
    description: str


class AttackFlowList(BaseModel):
    tactic_selection: list[tuple[str, str]] = Field(
        description="attack technique id to attack tactic id mapping using possible_tactics"
    )
    # additional_tactic_mapping: list[tuple[str, str]] = Field(description="the rest of tactic_mapping")
    items: list[AttackFlowItem]
    success: bool = Field(
        description="determines if there's any valid flow in <extractions>"
    )

    def model_post_init(self, context):
        return super().model_post_init(context)

    @property
    def tactic_mapping(self):
        return dict(self.tactic_selection)
