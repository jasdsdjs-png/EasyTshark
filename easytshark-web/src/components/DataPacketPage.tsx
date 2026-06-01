import React, { useState, useEffect, useImperativeHandle, forwardRef, useRef } from 'react';
import { Table, Pagination, Tree } from '@arco-design/web-react';
import { Typography } from '@arco-design/web-react';
import dayjs from 'dayjs';
import { apiFetchData, apiGet } from '../Api.ts';
import "../style/global.css";
import { Resizable } from 'react-resizable';
import 'react-resizable/css/styles.css';

import { hexCharCodeToStr, strTwoSplit, isInteger, padNumber } from '../util.ts'
const { Ellipsis } = Typography;

const CustomResizeHandle = forwardRef((props, ref) => {
  const { handleAxis, ...restProps } = props;
  return (
    <span
      ref={ref}
      className={`react-resizable-handle react-resizable-handle-${handleAxis}`}
      {...restProps}
      onClick={(e) => {
        e.stopPropagation();
      }}
    />
  );
});

const ResizableTitle = (props) => {
  const { onResize, width, ...restProps } = props;

  if (!width) {
    return <th {...restProps} />;
  }

  return (
    <Resizable
      width={width}
      height={0}
      handle={<CustomResizeHandle />}
      onResize={onResize}
      draggableOpts={{
        enableUserSelectHack: false,
      }}
    >
      <th {...restProps} />
    </Resizable>
  );
};

// 初始列定义
const initalColumns = [
  {
    title: '序号',
    dataIndex: 'frame_number',
    width: 80,
  },
  {
    title: '时间',
    dataIndex: 'timestamp',
    width: 230,
    render: (value) => {
      const split = value.toString().split('.');
      const s = `${dayjs(value * 1000).format('YYYY-MM-DD HH:mm:ss')}.${split[1]}`;
      return <Ellipsis showTooltip>{s}</Ellipsis>;
    }
  },
  {
    title: '源IP',
    dataIndex: 'src_ip',
    width: 150,
  },
  {
    title: '源IP归属地',
    dataIndex: 'src_location',
    width: 200
  },
  {
    title: '源端口',
    dataIndex: 'src_port',
    width: 100,
  },
  {
    title: '目的IP',
    dataIndex: 'dst_ip',
    width: 150,
  },
  {
    title: '目的IP归属地',
    dataIndex: 'dst_location',
    width: 200,
  },
  {
    title: '目的端口',
    dataIndex: 'dst_port',
    width: 100,
  },
  {
    title: '数据包大小',
    dataIndex: 'len',
    width: 200,
  },
  {
    title: '协议',
    dataIndex: 'protocol',
    width: 120,
  },
  {
    title: '信息',
    dataIndex: 'info',
    width: 350,
  },
];

const DataPacketPage = forwardRef(function DataPacketPage(props, ref) {

  const [reloadCount, setReloadCount] = useState(0)

  // 数据包列表相关
  const [loading, setLoading] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [pageSize, setPageSize] = useState(30);
  const [dataList, setDataList] = useState([]);
  const [currentRowId, setCurrentRowId] = useState(1);
  const [columns, setColumns] = useState(
    initalColumns.map((column, index) => {
      if (column.width) {
        return {
          ...column,
          onHeaderCell: (col) => ({
            width: col.width,
            onResize: handleResize(index),
          }),
        };
      }

      return column;
    })
  );

  // 协议树相关
  const [treeData, setTreeData] = useState([]);
  const [selectedKeys, setSelectedKeys] = useState([]);

  // 十六进制数据相关
  const [offsetData, setOffsetData] = useState([])
  const [hexData, setHexData] = useState([])
  const [ascData, setAscData] = useState([])
  const [selectedLeftHex, setSelectedLeftHex] = useState([])
  const [selectedRightHex, setSelectedRightHex] = useState([])

  // 动态抓包定时加载数据的定时器
  const timerRef = useRef(0);

  // 根据选中状态返回不同的类名
  const rowClassName = (record) => {
    return record['frame_number'] == currentRowId ? 'selected-row' : '';
  };


  function handleResize(index) {
    return (e, { size }) => {
      setColumns((prevColumns) => {
        const nextColumns = [...prevColumns];
        nextColumns[index] = { ...nextColumns[index], width: size.width };
        return nextColumns;
      });
    };
  }


  const loadData = async () => {
    setLoading(true);
    let proto = '';
    let sessionId = 0;
    if (props.match.params.type === 'arp') {
      proto = "ARP";
    } else if (props.match.params.type === 'icmp') {
      proto = "ICMP";
    } else if (props.match.params.type === 'icmpv6') {
      proto = "ICMPv6";
    } else if (props.match.params.type === 'detail') {
      sessionId = parseInt(props.match.params.sessionId)
    } else {
      proto = "";
    }
    const _data = await apiFetchData('/api/getPacketList', {
      pageSize: pageSize,
      pageNum: currentPage,
      proto: proto,
      session_id: sessionId
    });


    setDataList(_data.data);
    setTotal(_data.total);

    setLoading(false);
  };

  // 定义一个生成唯一ID的闭包
  const makeIdGenerator = () => {
    let idCounter = 0;
    return () => ++idCounter;
  };

  // 创建一个ID生成器实例
  const generateId = makeIdGenerator();
  const addUniqueID = (node) => {
    const updatedNode = { ...node, id: generateId().toString() };
    if (Array.isArray(updatedNode.field) && updatedNode.field.length > 0) {
      updatedNode.field = updatedNode.field.map(addUniqueID);
    }
    return updatedNode;
  };

  const loadPacketDetail = async () => {
    const _data = await apiFetchData('/api/getPacketDetail', {
      frameNumber: currentRowId
    });

    if (_data.data != null) {
      const tree = _data?.data.proto.map(addUniqueID);
      setTreeData(tree);
      transformHexData(_data?.data?.hexdata)
    } else {
      setTreeData([])
      transformHexData('')
    }
  };

  const renderTitle = (node) => {
    const title = node.dataRef.showname || node.dataRef.name || node.dataRef.show;
    if (node._level === 0) {
      return <span style={{ color: 'rgb(var(--primary-5))' }}>{title}</span>;
    }
    return title;
  };


  // 组装十六进制展示
  const transformHexData = (hex) => {
    const offsetData = []
    const hexData = []
    const ascData = []

    // 十六进制转换为ascii码
    const params = hexCharCodeToStr(hex)
    for (let i = 0; i < params.length; i++) {
      const asc = { label: params[i], key: i, show: false }
      // 如果是..，则表达找不到该ascii码，用虚拟.表达
      const str = ['换', '行', '无']
      if (str.includes(params[i])) {
        asc.label = '.'
        asc.show = true
      }
      ascData.push(asc)
    }
    const arr = strTwoSplit(hex).split(',')
    arr.map((item, index) => {
      hexData.push({ label: item, key: index })
    })
    // 判断是总偏移量个数是否为整数，不为整数向上取整
    let offset: any = ascData.length / 16
    if (!isInteger(offset)) {
      offset = parseInt(offset) + 1
    }
    // 计算偏移量 不够四位左侧补位0
    for (let i = 0; i < offset; i++) {
      const hex = padNumber((i * 16).toString(16), 4, 0)
      offsetData.push({ label: hex, key: i + 1 })
    }
    setOffsetData(offsetData)
    setHexData(hexData)
    setAscData(ascData)
  }


  // 点击节点高亮偏移量
  const handleNodeClick = (node, data) => {
    setSelectedKeys(node)
    const pos = parseInt(data.node?.props.pos)
    const size = parseInt(data.node?.props.size) + pos
    const leftArr = []
    const rightArr = []
    for (let i = pos; i < size; i++) {
      leftArr.push(i)
    }
    setSelectedRightHex([...leftArr])
    // 计算8位偏移量是否选中
    if (data.node && parseInt(data.node?.props.size) !== 0) {
      const posLeft = !isInteger((pos + 1) / 16) ? ((pos + 1) / 16 >> 0) + 1 : (pos + 1) / 16
      const sizeLeft = !isInteger(size / 16) ? (size / 16 >> 0) + 1 : size / 16
      for (let i = posLeft; i <= sizeLeft; i++) {
        rightArr.push(i)
      }
      setSelectedLeftHex([...rightArr])
    } else {
      setSelectedLeftHex([])
    }
  }

  // 重新加载数据
  const reloadData = () => {
    setDataList([])
    setTreeData([])
    setOffsetData([])
    setHexData([])
    setAscData([])
    setCurrentPage(1)
    setCurrentRowId(1)
    setReloadCount(reloadCount + 1)
  }

  // 暴露方法给父组件
  useImperativeHandle(ref, () => ({
    setCurrentRowId: setCurrentRowId,
    reloadData: reloadData,
  }));


  // 数据加载更新
  useEffect(() => {
    loadData();
  }, [currentPage, pageSize, props.match.params.type]);


  useEffect(() => {
    if (dataList.length > 0) {
      // 设置默认选中第一行
      setCurrentRowId(dataList[0].frame_number);
    }
  }, [dataList]);

  useEffect(() => {

    // 每次加载新的数据列表时，需要重新获取最新列表第一个数据包的详情
    loadPacketDetail()

  }, [currentRowId])


  // 如果是处于抓包中的状态，并且不是详情页，则周期性加载新数据
  useEffect(() => {
    const checkStatus = async () => {
      const _data = await apiGet('/api/getWorkStatus');
      if (_data.data.workStatus === 2) {
        loadData();
      } else {
        loadData();
        console.log("clearInterval: ", timerRef.current);
        clearInterval(timerRef.current);
        timerRef.current = 0;
      }
    };
  
    if (props.match.params.type !== 'detail') {
      let id = setInterval(checkStatus, 2000);
      timerRef.current = id;
      console.log("timerId: ", timerRef.current);
    }
  
    return () => {
      if (timerRef.current !== 0) {
        clearInterval(timerRef.current);
        timerRef.current = 0;
      }
    };
  }, [reloadCount]);

  
  return (
    <div>
      <div className="packet-table">
        <Table
          className='table-demo-resizable-column'
          // 通过 components 属性自定义表头单元格
          components={{
            header: {
              th: ResizableTitle,
            },
          }}
          // 使用合并后的列配置
          columns={columns}
          data={dataList}
          loading={loading}
          pagination={false}
          rowKey="frame_number"
          rowClassName={rowClassName}
          // 通过 scroll 属性设置固定表头（这里固定了 400px 高度内的表体）
          scroll={{ y: 360, x: '100%' }}
          onRow={(record) => ({
            onClick: () => {
              // 单选：点击任意一行就选中这一行
              setCurrentRowId(record.frame_number)
            },
          })}
        />
        <Pagination
          current={currentPage}
          showTotal
          sizeCanChange
          total={total}
          pageSize={pageSize}
          onChange={(page) => setCurrentPage(page)}
          onPageSizeChange={(size) => setPageSize(size)}
          style={{ marginTop: 16, textAlign: 'right', justifyContent: 'flex-end' }}
        />
      </div>
      <div className="detail-pannel">
        <div className="proto-tree">
          <Tree
            selectedKeys={selectedKeys}
            treeData={treeData}
            blockNode
            showLine
            autoExpandParent={false}
            fieldNames={{
              key: 'id',
              title: 'showname',
              children: 'field',
            }}
            renderTitle={renderTitle}
            onSelect={handleNodeClick}
          />
        </div>
        <div className="hex-data">
          <div className="offset">
            <div className="left pdt8 pdb8">
              {offsetData.map(item => {
                return <span key={item.key} className={selectedLeftHex.indexOf(item.key) !== -1 ? 'selected' : ''}>{item.label}</span>
              })}
            </div>
            <div className="center">
              {hexData.map(item => {
                return <span id={item.key} key={item.key} className={selectedRightHex.indexOf(item.key) !== -1 ? 'selected' : ''}>{item.label}</span>
              })}
            </div>
            <div className="right">
              {ascData.map(item => {
                return <span key={item.key} className={selectedRightHex.indexOf(item.key) !== -1 ? 'selected' : ''} style={item.show ? { color: '#bbb' } : {}}>{item.label}</span>
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
});

export default DataPacketPage;
