import type { ServerConfig } from '../src/utils/ServerConfig';
import { connect } from 'ngrok';
import { startServer } from '../src/index';
import { setupAgent } from '../src/utils/agent';

const run = async () => {
  const endpoint = await connect(3001);

  // Call setupAgent with the required parameters
  const agent = await setupAgent({
    name: 'Aries Test Agent', // Pass the agent name
    endpoints: [endpoint], // Pass the endpoint
    port: 3001, // Pass the port
  });

  const conf: ServerConfig = {
    port: 3000,
    cors: true,
  };

  await startServer(agent, conf);
};

run();
