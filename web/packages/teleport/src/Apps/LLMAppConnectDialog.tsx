/**
 * Teleport
 * Copyright (C) 2026 Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import { Box, ButtonSecondary, Stack, Text } from 'design';
import Dialog, {
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from 'design/Dialog';
import {
  TextSelectCopy,
  TextSelectCopyMulti,
} from 'shared/components/TextSelectCopy';

import { generateTshLoginCommand } from 'teleport/lib/util';
import { App } from 'teleport/services/apps';
import useStickyClusterId from 'teleport/useStickyClusterId';
import useTeleport from 'teleport/useTeleport';

/**
 * Port the instructions pin the local proxy to, so Step 2 and Step 3 can
 * reference a concrete address instead of a randomized one.
 */
const LOCAL_PROXY_PORT = '3000';
const localProxyURL = `http://127.0.0.1:${LOCAL_PROXY_PORT}`;

export function LLMAppConnectDialog(props: { app: App; onClose: () => void }) {
  const { app } = props;
  const ctx = useTeleport();
  const { clusterId } = useStickyClusterId();
  const { username, authType } = ctx.storeUser.state;
  const accessRequestId = ctx.storeUser.getAccessRequestId();

  return (
    <Dialog
      dialogCss={() => ({
        maxWidth: '600px',
        width: '100%',
      })}
      disableEscapeKeyDown={false}
      onClose={props.onClose}
      open={true}
    >
      <DialogHeader mb={4}>
        <DialogTitle>Use "{app.name}" inference endpoint</DialogTitle>
      </DialogHeader>

      <DialogContent>
        <Stack gap={4} fullWidth>
          <Stack fullWidth gap={2}>
            <Text>
              <Text bold as="span">
                Step 1
              </Text>
              {' - Log in to Teleport'}
            </Text>

            <TextSelectCopy
              text={generateTshLoginCommand({
                authType,
                username,
                clusterId,
                accessRequestId,
              })}
            />
          </Stack>

          <Stack fullWidth gap={2}>
            <Text>
              <Text bold as="span">
                Step 2
              </Text>
              {' - Start a local proxy for the inference endpoint'}
            </Text>

            <TextSelectCopy
              text={`tsh proxy app ${app.name} --port ${LOCAL_PROXY_PORT}`}
            />
            <Box>
              This listens on {localProxyURL}. Every request is authenticated
              and audited by Teleport, which also injects the provider API key —
              so no real key is needed locally.
            </Box>
          </Stack>

          <Stack fullWidth gap={2}>
            <Text>
              <Text bold as="span">
                Step 3
              </Text>
              {' - Point your LLM client at the local proxy'}
            </Text>

            <Box>
              <Text bold>
                Claude Code, Claude Agent SDK, or any Anthropic client
              </Text>
            </Box>
            <TextSelectCopyMulti
              lines={[
                { text: `export ANTHROPIC_BASE_URL=${localProxyURL}` },
                {
                  comment:
                    'Any non-empty value works; Teleport swaps in the real key.',
                  text: 'export ANTHROPIC_API_KEY=teleport',
                },
              ]}
            />
            <Box>Then run Claude Code as usual:</Box>
            <TextSelectCopy text="claude" />

            <Box mt={2}>
              <Text bold>Codex, or any OpenAI-compatible client</Text>
            </Box>
            <TextSelectCopyMulti
              lines={[
                { text: `export OPENAI_BASE_URL=${localProxyURL}/v1` },
                {
                  comment:
                    'Any non-empty value works; Teleport swaps in the real key.',
                  text: 'export OPENAI_API_KEY=teleport',
                },
              ]}
            />
            <Box>Then start Codex:</Box>
            <TextSelectCopy text="codex" />
          </Stack>
        </Stack>
      </DialogContent>

      <DialogFooter>
        <ButtonSecondary onClick={props.onClose}>Close</ButtonSecondary>
      </DialogFooter>
    </Dialog>
  );
}
