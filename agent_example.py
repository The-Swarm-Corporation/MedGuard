from dotenv import load_dotenv
from medinsight.agent import MedInsightPro

from medguard.main import MedGuard

load_dotenv()

# Initialize the MedInsight Pro agent
med_agent = MedInsightPro(max_articles=10)


# MedGuard
model = MedGuard(agent=med_agent, user="admin")

print(
    model.run_agent(
        "Patient Information: Name - Kye Gomez, Social Security Number - 888-233-2322, Email - kye@swarms.world. Diagnosis: Pennuenmoia. Treatment Query: What is the most effective treatment plan for a patient diagnosed with Pennuenmoia?"
    )
)
