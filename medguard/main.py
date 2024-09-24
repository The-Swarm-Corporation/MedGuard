from typing import List, Dict, Any

from loguru import logger
from swarms import Agent

from medguard.de_identifier import Deidentifier
from medguard.secure_communications import SecureCommunicationAES
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from pydantic import BaseModel, Field


class MedGuardInputLog(BaseModel):
    agent_id: str
    agent_config: Dict[Any, Any]
    user_id: str
    user_role: str
    task: str
    data_sources: str
    output_data: str
    timestamp: str = Field(
        ...,
    )


class MedGuard:
    """
    A class to manage and ensure HIPAA compliance for large language model (LLM) agents.

    This class initializes with an optional agent or list of agents, and provides methods to run and wrap agents for HIPAA compliance.
    """

    def __init__(
        self,
        agent: Agent = None,
        agents: List[Agent] = None,
        user: str = None,
        *args,
        **kwargs,
    ):
        """
        Initialize MedGuard with an optional agent or list of agents.

        :param agent: A single Agent instance to be managed.
        :param agents: A list of Agent instances to be managed.
        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.
        """
        self.agent = agent
        self.agents = agents
        self.user = user
        self.key = SecureCommunicationAES()
        self.deidentifer = Deidentifier()
        logger.info(f"MedGuard initialized with agent: {agent}")
        logger.info(
            f"MedGuard initialized with agents: {len(agents)}"
        )

    def run_agent(self, task: str, *args, **kwargs):
        """
        Run the MedGuard instance with the initialized agent(s) ensuring HIPAA compliance.

        This method implements the actual logic to run the MedGuard instance with the configured agent(s) while adhering to HIPAA compliance guidelines.
        """
        logger.info(
            "Running MedGuard instance with HIPAA compliance..."
        )

        # De-identify sensitive information in the task before encryption
        deidentified_task = self.deidentifer.deidentify(task)

        # Encrypt the de-identified task for secure transmission
        encrypted_task = self.key.encrypt(
            deidentified_task, self.user
        )

        # Decrypt the task for processing by the agent
        decrypted_task = self.key.decrypt(encrypted_task)

        # Run the task with the agent
        output = self.agent.run(decrypted_task, *args, **kwargs)

        # De-identify sensitive information in the output before returning
        deidentified_output = self.deidentifer.deidentify(output)

        return deidentified_output

    def wrap_agent(self, agent: Agent):
        """
        Wrap a given agent with MedGuard for HIPAA compliance.

        :param agent: The Agent instance to be wrapped for HIPAA compliance.
        """
        self.agent = agent
        logger.info(
            f"Agent wrapped with MedGuard for HIPAA compliance: {agent.agent_name}"
        )

    def run_agent_concurrently(
        self, tasks: List[str], *args, **kwargs
    ):
        """
        Run multiple tasks concurrently with the initialized agent(s) ensuring HIPAA compliance.

        :param tasks: A list of tasks to be processed concurrently.
        """

        results = []

        with ThreadPoolExecutor() as executor:
            future_to_task = {
                executor.submit(
                    self.run_agent, task, *args, **kwargs
                ): task
                for task in tasks
            }

            for future in as_completed(future_to_task):
                task = future_to_task[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(
                        f"Task {task} generated an exception: {e}"
                    )

        return results
