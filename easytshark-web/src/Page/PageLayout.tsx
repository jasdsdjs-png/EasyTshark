import { Layout, Menu, Button } from '@arco-design/web-react';
import "../style/global.css"
import { HashRouter, Route, Link } from 'react-router-dom';
import Navbar from '../components/Navbar.tsx';
import DataPacketPage from '../components/DataPacketPage.tsx';
import SessionPage from '../components/SessionPage.tsx';
import React, { useState, useEffect, useRef } from 'react';

import {
  IconMenuFold,
  IconMenuUnfold,
  IconApps,
  IconBug,
  IconBulb,
  IconBook,
} from '@arco-design/web-react/icon';

const MenuItem = Menu.Item;
const SubMenu = Menu.SubMenu;

const Sider = Layout.Sider;
const Header = Layout.Header;
const Footer = Layout.Footer;
const Content = Layout.Content;

function PageLayout() {

  const DataPacketPageRef = useRef(null);

  const updateData = () => {
    DataPacketPageRef.current.reloadData()
  }

  return (
    <HashRouter>
      {/* 外层 Layout 占满整个视口 */}
      <Layout style={{ height: '100vh', overflow: 'hidden' }}>
        {/* Header 固定高度（假设 64px） */}
        <Header style={{ height: '64px', lineHeight: '64px' }}>
          <Navbar onUpdateData={updateData} />
        </Header>

        {/* 内层 Layout 高度 = 100vh - Header高度 - padding高度 */}
        <Layout style={{ 
          height: 'calc(100vh - 74px)', // 关键计算
          display: 'flex',
        }}>
          {/* Sider 固定宽度，高度继承父级 */}
          <Sider style={{ width: '200px', height: '100%' }}>
            <Menu
              style={{ width: '100%', height: '100%' }}
              hasCollapseButton
              defaultOpenKeys={['0']}
              defaultSelectedKeys={['0_1']}
            >
              <SubMenu
                key='0'
                title={<><IconApps /> 数据包分析</>}
              >
                <MenuItem key='allPackets'><Link to="/data/dataPacket/all">全部数据包</Link></MenuItem>
                <MenuItem key='arpPackets'><Link to="/data/dataPacket/arp">ARP数据包</Link></MenuItem>
                <MenuItem key='icmpPackets'><Link to="/data/dataPacket/icmp">ICMP数据包</Link></MenuItem>
                <MenuItem key='icmpv6Packets'><Link to="/data/dataPacket/icmpv6">ICMPv6数据包</Link></MenuItem>
              </SubMenu>
              <SubMenu
                key='1'
                title={<><IconBug /> 会话分析</>}
              >
                <MenuItem key='tcpSession'><Link to="/data/session/tcp">TCP会话</Link></MenuItem>
                <MenuItem key='udpSession'><Link to="/data/session/udp">UDP会话</Link></MenuItem>
                <MenuItem key='dnsSession'><Link to="/data/session/dns">DNS会话</Link></MenuItem>
                <MenuItem key='httpSession'><Link to="/data/session/http">HTTP会话</Link></MenuItem>
                <MenuItem key='tlsSession'><Link to="/data/session/tls">SSL/TLS会话</Link></MenuItem>
                <MenuItem key='sshSession'><Link to="/data/session/ssh">SSH会话</Link></MenuItem>
              </SubMenu>
              <SubMenu
                key='2'
                title={<><IconBulb /> 统计分析</>}
              >
                <MenuItem key='ipCount'>IP统计</MenuItem>
                <MenuItem key='protoCount'>协议统计</MenuItem>
                <MenuItem key='countryCount'>国家统计</MenuItem>
              </SubMenu>
            </Menu>
          </Sider>

          {/* Content 自动填充剩余宽度，并允许滚动 */}
          <Content style={{ 
            flex: 1, 
            overflow: 'auto', // 内容超出时滚动
            padding: '16px', // 可选：添加内边距
          }}>
            {/* <Route path="/data/dataPacket/:type" component={DataPacketPage} /> */}

            <Route 
              path="/data/dataPacket/:type" 
              render={(props) => (
                <DataPacketPage {...props} ref={DataPacketPageRef} />
              )}
            />
            <Route path="/data/session/:type" component={SessionPage} />
          </Content>
        </Layout>
      </Layout>
    </HashRouter>
  );
}

export default PageLayout;