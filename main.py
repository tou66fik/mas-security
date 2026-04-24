import asyncio
from agents.adi import AgentADI
from agents.asi import AgentASI
from agents.acsrf import AgentACSRF
from agents.amitm import AgentAMITM
from agents.act import AgentACT
from agents.aapprove import AgentAPROVE
from orchestrator_prod import AgentAA, AgentAR
from mitre_enricher import MITREEnricher

async def main():
    enricher = MITREEnricher()
    agents = [AgentADI(), AgentASI(), AgentACSRF(), AgentAMITM(), AgentACT(),
              AgentAA(enricher), AgentAR(), AgentAPROVE(slack_webhook="", timeout=25)]
    await asyncio.gather(*(a.run(a.setup) for a in agents))

if __name__=="__main__": asyncio.run(main())
