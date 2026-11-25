from abc import ABC, abstractmethod

from lab.contracts import Job


class AgentAdapter(ABC):
    @abstractmethod
    async def execute(self, job: Job) -> dict:
        """Return correlated proposals and observed replies within fixed budgets."""
        raise NotImplementedError

