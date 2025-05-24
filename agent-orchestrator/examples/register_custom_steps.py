from examples.custom_pipeline_step import CustomAlertEnrichmentStep


def register_custom_steps(pipeline_processor):
    """
    Register custom pipeline steps with the pipeline processor

    This function is called from the agent_manager after initializing the
    standard pipeline steps, allowing users to extend the pipeline
    with custom functionality.

    Args:
        pipeline_processor: The PipelineProcessor instance to register steps with
    """
    # Register the custom alert enrichment step
    pipeline_processor.register_step("alert_enrichment", CustomAlertEnrichmentStep())

    # Add other custom steps here as needed
    # pipeline_processor.register_step("your_custom_step", YourCustomStep())

    return pipeline_processor
