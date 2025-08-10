import abc
from typing import Any, TypeVar

from src.logger import logger

# Type for pipeline step result
T = TypeVar("T", bound=dict[str, Any])


class PipelineStep(abc.ABC):
    """Base class for all pipeline steps"""

    @abc.abstractmethod
    async def process(self, data: dict[str, Any]) -> dict[str, Any]:
        """Process the data and return the result"""
        pass

    @property
    def required_inputs(self) -> list[str]:
        """Return list of keys required in the input data"""
        return []

    @property
    def provided_outputs(self) -> list[str]:
        """Return list of keys provided in the output data"""
        return []


class PipelineProcessor:
    """Manages and executes pipeline steps"""

    def __init__(self):
        self.steps: dict[str, PipelineStep] = {}

    def register_step(self, name: str, step: PipelineStep) -> None:
        """Register a pipeline step with a name"""
        self.steps[name] = step

    async def process(
        self,
        initial_data: dict[str, Any],
        pipeline: list[str],
        step_config: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Process data through a sequence of pipeline steps

        Args:
            initial_data: The initial data to process
            pipeline: List of step names to execute in order
            step_config: Optional configuration for each step

        Returns:
            The final data after all processing
        """
        data = initial_data.copy()
        step_config = step_config or {}

        for step_name in pipeline:
            if step_name not in self.steps:
                raise ValueError(f"Pipeline step '{step_name}' not found")
            logger.info(f"Processing step: {step_name}")

            step = self.steps[step_name]

            # Check if all required inputs are available
            missing_inputs = [
                input_key for input_key in step.required_inputs if input_key not in data
            ]

            if missing_inputs:
                raise ValueError(
                    f"Missing required inputs for step '{step_name}': {missing_inputs}"
                )

            # Process the step
            step_result = await step.process({**data, **step_config.get(step_name, {})})

            # Update data with the step results
            data.update(step_result)

        return data
