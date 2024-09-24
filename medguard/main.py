import uuid
from typing import List, Dict, Any

from loguru import logger
from swarms import Agent

from medguard.de_identifier import Deidentifier
from medguard.secure_communications import SecureCommunicationAES
from concurrent.futures import ThreadPoolExecutor, as_completed
from pydantic import BaseModel, Field

import time
from typing import List, Dict, Any

class MedGuardInputLog(BaseModel):
    id: str = Field(default_factory=uuid.uuid4.hex)
    agent_id: str = Field(default="")
    agent_config: Dict[Any, Any] = Field(default={})
    user_id: str = Field(default="")
    user_role: str = Field(default="")
    task: str = Field(default="")
    data_sources: str = Field(default="")
    timestamp: str = Field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))

class MedGuardInputLogs(BaseModel):
    output: str = Field(default="")
    timestamp: str = Field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    cleaned_task: str = Field(default="")
    encrypted_input: str = Field(default="")
    time: str = Field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))

class MedGuardOutputLog(BaseModel):
    id: str = Field(default_factory=uuid.uuid4.hex)
    input_config: MedGuardInputLog
    outputs: List[MedGuardInputLogs] = Field(default=[])
    time_stamp: str = Field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))


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
        data_sources: List[str] = None, # PDFS, CSVs, any medical data sources available
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
        self.data_sources = data_sources
        self.key = SecureCommunicationAES(roles=[self.user])
        self.deidentifer = Deidentifier()

        # self.logs = MedGuardInputLog
        self.logs = MedGuardOutputLog(
            input_config=MedGuardInputLog(
                agent.id,
                agent.to_dict(),
                user_id=uuid.uuid4.hex(),
                user_role=user,
                task="",
                data_sources=data_sources,
            ),
            outputs=[],
        )

    def run_agent(self, task: str, *args, **kwargs):
        """
        Run the MedGuard instance with the initialized agent(s) ensuring HIPAA compliance.

        This method implements the actual logic to run the MedGuard instance with the configured agent(s) while adhering to HIPAA compliance guidelines.
        """
        self.logs.input_config.task = task
        
        logger.info(
            "Running MedGuard instance with HIPAA compliance..."
        )

        # De-identify sensitive information in the task before encryption
        deidentified_task = self.deidentifer.deidentify(task)
        logger.info(f"De-identified task: {deidentified_task}")

        # Encrypt the de-identified task for secure transmission
        encrypted_task = self.key.encrypt(
            deidentified_task, self.user
        )
        logger.info(f"Encrypted task: {encrypted_task}")

        # Decrypt the task for processing by the agent
        decrypted_task = self.key.decrypt(encrypted_task, self.user)
        logger.info(f"Decrypted task: {decrypted_task}")

        # Run the task with the agent
        output = self.agent.run(decrypted_task, *args, **kwargs)
        logger.info(f"Agent output: {output}")

        # De-identify sensitive information in the output before returning
        deidentified_output = self.deidentifer.deidentify(output)
        logger.info(f"De-identified output: {deidentified_output}")
        
        # Update the loogs
        self.logs.outputs.append(
            MedGuardInputLogs(
                output = output,
                cleaned_task=deidentified_task,
                encrypted_input=encrypted_task,
            )
        )

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
