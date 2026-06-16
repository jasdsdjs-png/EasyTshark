import { Layout, Menu } from '@arco-design/web-react';
import '../style/global.css';
import { Link, Route } from 'react-router-dom';
import Navbar from '../components/Navbar.tsx';
import DataPacketPage from '../components/DataPacketPage.tsx';
import SessionPage from '../components/SessionPage.tsx';
import StatsPage from '../components/StatsPage.tsx';
import React, { useRef } from 'react';

import {
  IconApps,
  IconBug,
  IconBulb,
} from '@arco-design/web-react/icon';

const MenuItem = Menu.Item;
const SubMenu = Menu.SubMenu;

const Sider = Layout.Sider;
const Header = Layout.Header;
const Content = Layout.Content;

function PageLayout() {
  const DataPacketPageRef = useRef(null);

  const updateData = () => {
    DataPacketPageRef.current?.reloadData();
  };

  return (
    <>
      <Layout style={{ height: '100vh', overflow: 'hidden' }}>
        <Header style={{ height: '64px', lineHeight: '64px' }}>
          <Navbar onUpdateData={updateData} />
        </Header>

        <Layout
          style={{
            height: 'calc(100vh - 74px)',
            display: 'flex',
          }}
        >
          <Sider style={{ width: '200px', height: '100%' }}>
            <Menu
              style={{ width: '100%', height: '100%' }}
              hasCollapseButton
              defaultOpenKeys={['0']}
              defaultSelectedKeys={['allPackets']}
            >
              <SubMenu key="0" title={<><IconApps /> 数据包分析</>}>
                <MenuItem key="allPackets"><Link to="/data/dataPacket/all">全部数据包</Link></MenuItem>
                <MenuItem key="arpPackets"><Link to="/data/dataPacket/arp">ARP数据包</Link></MenuItem>
                <MenuItem key="icmpPackets"><Link to="/data/dataPacket/icmp">ICMP数据包</Link></MenuItem>
                <MenuItem key="icmpv6Packets"><Link to="/data/dataPacket/icmpv6">ICMPv6数据包</Link></MenuItem>
              </SubMenu>
              <SubMenu key="1" title={<><IconBug /> 会话分析</>}>
                <MenuItem key="tcpSession"><Link to="/data/session/tcp">TCP会话</Link></MenuItem>
                <MenuItem key="udpSession"><Link to="/data/session/udp">UDP会话</Link></MenuItem>
                <MenuItem key="dnsSession"><Link to="/data/session/dns">DNS会话</Link></MenuItem>
                <MenuItem key="httpSession"><Link to="/data/session/http">HTTP会话</Link></MenuItem>
                <MenuItem key="tlsSession"><Link to="/data/session/tls">SSL/TLS会话</Link></MenuItem>
                <MenuItem key="sshSession"><Link to="/data/session/ssh">SSH会话</Link></MenuItem>
              </SubMenu>
              <SubMenu key="2" title={<><IconBulb /> 统计分析</>}>
                <MenuItem key="ipCount"><Link to="/data/stats/ip">IP统计</Link></MenuItem>
                <MenuItem key="protoCount"><Link to="/data/stats/proto">协议统计</Link></MenuItem>
                <MenuItem key="countryCount"><Link to="/data/stats/country">国家统计</Link></MenuItem>
              </SubMenu>
            </Menu>
          </Sider>

          <Content
            style={{
              flex: 1,
              overflow: 'auto',
              padding: '16px',
            }}
          >
            <Route
              path="/data/dataPacket/:type"
              render={(props) => (
                <DataPacketPage {...props} ref={DataPacketPageRef} />
              )}
            />
            <Route path="/data/session/:type" component={SessionPage} />
            <Route path="/data/stats/:type" component={StatsPage} />
          </Content>
        </Layout>
      </Layout>
    </>
  );
}

export default PageLayout;
