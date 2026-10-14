"""Provider doubles (openai-stub, anthropic-stub, ollama-stub) with seeded chaos knobs.

All three expose the OpenAI-compatible surface (B2 cut): chat completions with streaming,
embeddings and models. Chaos is applied here, behind the real gateway (ML §8.1).
"""

from sibyl_sim.doubles.app import control_app, doubles_app
from sibyl_sim.doubles.engine import Decision, Double
from sibyl_sim.doubles.knobs import KnobError, Knobs
from sibyl_sim.doubles.state import SimState, build_state

__all__ = [
    "Decision",
    "Double",
    "KnobError",
    "Knobs",
    "SimState",
    "build_state",
    "control_app",
    "doubles_app",
]
