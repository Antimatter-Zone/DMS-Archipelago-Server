"""Controlled source qualification client. Reads a synthetic test password from a fixed private file."""
import asyncio,json
from pathlib import Path
import websockets
ROOT=Path('/home/container/.amz')
async def run():
    config=json.loads((ROOT/'current.json').read_text())
    password=(ROOT/'old-password').read_text() if (ROOT/'probe-mode').read_text()=='old' else config['password']
    async with websockets.connect('ws://127.0.0.1:'+str(config['port'])) as websocket:
        info=json.loads(await websocket.recv())
        assert info[0]['cmd']=='RoomInfo'
        await websocket.send(json.dumps([{'cmd':'Connect','password':password,'name':'Player1','game':'APQuest','uuid':'amz-source-runtime-probe','version':{'major':0,'minor':6,'build':8,'class':'Version'},'items_handling':7,'tags':['AP'],'slot_data':False}]))
        connected=False;refused=False
        for count in range(10):
            values=json.loads(await asyncio.wait_for(websocket.recv(),5))
            if any(value.get('cmd')=='Connected' for value in values):connected=True;break
            if any(value.get('cmd')=='ConnectionRefused' for value in values):refused=True;break
        if connected:
            await websocket.send(json.dumps([{'cmd':'LocationChecks','locations':[1000]}]))
        print(json.dumps({'authenticated':connected,'refused':refused}),flush=True)
        if connected:
            for count in range(100):
                if (ROOT/'probe-release').exists():break
                await asyncio.sleep(.2)
asyncio.run(run())
