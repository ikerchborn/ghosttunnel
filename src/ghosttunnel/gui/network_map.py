import logging


try:
    from PyQt6.QtCore import Qt, QPointF
    from PyQt6.QtGui import QBrush, QColor, QPen, QFont, QPainterPath, QPainter
    from PyQt6.QtWidgets import (
        QGraphicsView, QGraphicsScene,
        QGraphicsPathItem, QGraphicsTextItem, QGraphicsRectItem
    )
except ImportError:
    pass

logger = logging.getLogger(__name__)

class NodeItem(QGraphicsRectItem):
    def __init__(self, title: str, subtitle: str, x: float, y: float, w: float = 180, h: float = 60):
        super().__init__(-w / 2, -h / 2, w, h)
        self.setPos(x, y)
        self.setBrush(QBrush(QColor("#0a0a0a")))
        self.setPen(QPen(QColor("#00ff41"), 2))
        
        self.title_item = QGraphicsTextItem(title, self)
        self.title_item.setDefaultTextColor(QColor("#00ff41"))
        font = QFont("Consolas", 12, QFont.Weight.Bold)
        self.title_item.setFont(font)
        
        self.subtitle_item = QGraphicsTextItem(subtitle, self)
        self.subtitle_item.setDefaultTextColor(QColor("#8b949e"))
        sub_font = QFont("Consolas", 9)
        self.subtitle_item.setFont(sub_font)
        
        self._align_text()

    def update_text(self, title: str, subtitle: str) -> None:
        self.title_item.setPlainText(title)
        self.subtitle_item.setPlainText(subtitle)
        self._align_text()
        
    def _align_text(self) -> None:
        rect = self.rect()
        t_rect = self.title_item.boundingRect()
        s_rect = self.subtitle_item.boundingRect()
        
        self.title_item.setPos(
            rect.center().x() - t_rect.width() / 2,
            rect.top() + 5
        )
        self.subtitle_item.setPos(
            rect.center().x() - s_rect.width() / 2,
            rect.bottom() - s_rect.height() - 5
        )

class EdgeItem(QGraphicsPathItem):
    def __init__(self, start_node: NodeItem, end_node: NodeItem):
        super().__init__()
        self.start_node = start_node
        self.end_node = end_node
        self.setZValue(-1)
        self.setPen(QPen(QColor("#00ff41"), 2, Qt.PenStyle.SolidLine))
        self.update_path()

    def update_path(self) -> None:
        start = self.start_node.scenePos()
        end = self.end_node.scenePos()
        
        # Draw from right edge of start to left edge of end
        start_x = start.x() + self.start_node.rect().width() / 2
        end_x = end.x() - self.end_node.rect().width() / 2
        
        path = QPainterPath(QPointF(start_x, start.y()))
        # simple straight line for now
        path.lineTo(QPointF(end_x, end.y()))
        self.setPath(path)

    def set_status(self, secure: bool, leaking: bool = False) -> None:
        if leaking:
            self.setPen(QPen(QColor("#ff003c"), 2, Qt.PenStyle.DashLine))
        elif secure:
            self.setPen(QPen(QColor("#00ff41"), 2, Qt.PenStyle.SolidLine))
        else:
            self.setPen(QPen(QColor("#8b949e"), 2, Qt.PenStyle.DotLine))

class NetworkMapWidget(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setBackgroundBrush(QBrush(QColor("#000000")))
        self.setStyleSheet("border: 1px solid #00ff41;")
        
        # Disable scrollbars, we will fit in view
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        # Build nodes
        self.node_local = NodeItem("Local Machine", "Waiting...", -300, 0)
        self.node_vpn = NodeItem("VPN Tunnel", "Disconnected", 0, 0)
        self.node_exit = NodeItem("Exit Node", "Internet", 300, 0)

        self.scene.addItem(self.node_local)
        self.scene.addItem(self.node_vpn)
        self.scene.addItem(self.node_exit)

        # Build edges
        self.edge_local_vpn = EdgeItem(self.node_local, self.node_vpn)
        self.edge_vpn_exit = EdgeItem(self.node_vpn, self.node_exit)
        self.scene.addItem(self.edge_local_vpn)
        self.scene.addItem(self.edge_vpn_exit)

        # Direct leak edge (Local -> Exit bypassing VPN)
        self.edge_leak = EdgeItem(self.node_local, self.node_exit)
        self.edge_leak.set_status(secure=False, leaking=True)
        self.edge_leak.hide()  # hidden by default
        self.scene.addItem(self.edge_leak)

        # Firewall barrier icon
        self.fw_barrier = QGraphicsTextItem("🛡️")
        font = QFont("Consolas", 24)
        self.fw_barrier.setFont(font)
        # Position it on the local->vpn line
        self.fw_barrier.setPos(-160, -20)
        self.scene.addItem(self.fw_barrier)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def update_graph(self, status: dict, leak_data: dict | None = None) -> None:
        # Update Local Machine
        ifaces = status.get("physical_ifaces", [])
        iface_str = ", ".join(ifaces) if ifaces else "eth0/wlan0"
        self.node_local.update_text("Local Machine", iface_str)

        # Update VPN Node
        vpn_iface = status.get("vpn_iface", "none")
        mode = status.get("mode", "unknown")
        fw_active = status.get("firewall_active", False)
        panic = status.get("panic_mode", False)
        
        if mode == "vpn-up" and vpn_iface:
            self.node_vpn.update_text("VPN Tunnel", vpn_iface)
        else:
            self.node_vpn.update_text("VPN Tunnel", "Disconnected")

        # Update Exit Node
        if leak_data:
            ip = leak_data.get("public_ip", "Unknown")
            cc = leak_data.get("country", "Unknown")
            self.node_exit.update_text(ip, cc)

        # Update Paths & Barriers
        if panic:
            self.edge_local_vpn.set_status(secure=False)
            self.edge_vpn_exit.set_status(secure=False)
            self.fw_barrier.setPlainText("🛑")
            self.edge_leak.hide()
        elif fw_active:
            self.edge_local_vpn.set_status(secure=True)
            self.edge_vpn_exit.set_status(secure=True)
            self.fw_barrier.setPlainText("🛡️")
            self.edge_leak.hide()
        else:
            # Firewall is off, traffic could be leaking
            self.edge_local_vpn.set_status(secure=False)
            self.edge_vpn_exit.set_status(secure=False)
            self.fw_barrier.setPlainText("🔓")
            if mode != "vpn-up":
                self.edge_leak.show()
                # Update leak path specifically for bypass
                path = QPainterPath(QPointF(self.node_local.scenePos().x() + 90, self.node_local.scenePos().y()))
                path.quadTo(QPointF(0, 150), QPointF(self.node_exit.scenePos().x() - 90, self.node_exit.scenePos().y()))
                self.edge_leak.setPath(path)
            else:
                self.edge_leak.hide()

        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-20, -20, 20, 20))
        self.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)
