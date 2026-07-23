// Canvas-based History Chart Component (Gnome System Monitor style)
class HistoryChart {
    constructor(canvasId, label1, label2, maxVal = 100, isNetwork = false) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.label1 = label1;
        this.label2 = label2;
        this.maxVal = maxVal;
        this.isNetwork = isNetwork;
        this.data1 = Array.from({length: 60}, () => 0);
        this.data2 = Array.from({length: 60}, () => 0);
    }

    pushValues(val1, val2) {
        if (!this.canvas) return;
        this.data1.push(val1);
        if (this.data1.length > 60) this.data1.shift();
        
        if (val2 !== undefined) {
            this.data2.push(val2);
            if (this.data2.length > 60) this.data2.shift();
        }
        this.draw();
    }

    draw() {
        if (!this.canvas || !this.ctx) return;
        const ctx = this.ctx;
        const width = this.canvas.width;
        const height = this.canvas.height;
        ctx.clearRect(0, 0, width, height);

        // Offset drawing area by 55px on left for Y-axis values
        const startX = 55;
        const endX = width - 15;
        const plotWidth = endX - startX;

        // Draw background grid lines
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
        ctx.lineWidth = 1;
        for (let i = 0; i <= 4; i++) {
            const y = (i / 4) * (height - 20) + 10;
            ctx.beginPath();
            ctx.moveTo(startX, y);
            ctx.lineTo(endX, y);
            ctx.stroke();
        }
        for (let i = 0; i <= 10; i++) {
            const x = startX + (i / 10) * plotWidth;
            ctx.beginPath();
            ctx.moveTo(x, 10);
            ctx.lineTo(x, height - 10);
            ctx.stroke();
        }

        // Draw Y-axis labels on the left
        ctx.font = '10px Inter, sans-serif';
        ctx.fillStyle = '#64748b';
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        for (let i = 0; i <= 4; i++) {
            const y = (i / 4) * (height - 20) + 10;
            const val = this.maxVal * (1 - i / 4);
            let label = '';
            if (this.isNetwork) {
                label = val >= 1024 ? `${(val / 1024).toFixed(1)} MB/s` : `${Math.round(val)} KB/s`;
            } else {
                label = `${Math.round(val)}%`;
            }
            ctx.fillText(label, startX - 8, y);
        }

        // Draw line 1 (e.g., CPU, Memory, or Network Rx)
        this.drawPath(this.data1, '#3b82f6', 2, startX, plotWidth);
        
        // Draw line 2 if label2 exists (e.g., Swap or Network Tx)
        if (this.label2) {
            this.drawPath(this.data2, '#10b981', 2, startX, plotWidth);
        }

        // Draw Legend/Values overlay (top-left inside grid)
        ctx.font = '11px Inter, sans-serif';
        ctx.textAlign = 'left';
        
        if (this.isNetwork) {
            const rxVal = this.data1[this.data1.length - 1];
            const txVal = this.data2[this.data2.length - 1];
            ctx.fillStyle = '#3b82f6';
            ctx.fillText(`${this.label1}: ${rxVal.toFixed(1)} KB/s`, startX + 10, 20);
            ctx.fillStyle = '#10b981';
            ctx.fillText(`${this.label2}: ${txVal.toFixed(1)} KB/s`, startX + 10, 35);
        } else {
            const val1 = this.data1[this.data1.length - 1];
            ctx.fillStyle = '#3b82f6';
            ctx.fillText(`${this.label1}: ${Math.round(val1)}%`, startX + 10, 20);
            if (this.label2) {
                const val2 = this.data2[this.data2.length - 1];
                ctx.fillStyle = '#10b981';
                ctx.fillText(`${this.label2}: ${Math.round(val2)}%`, startX + 10, 35);
            }
        }
    }

    drawPath(data, color, lineWidth, startX, plotWidth) {
        const ctx = this.ctx;
        const height = this.canvas.height;
        ctx.strokeStyle = color;
        ctx.lineWidth = lineWidth;
        ctx.beginPath();

        const step = plotWidth / 59;
        data.forEach((val, index) => {
            const x = startX + index * step;
            const pct = Math.min(val / this.maxVal, 1.0);
            const y = height - 10 - pct * (height - 20);
            if (index === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        });
        ctx.stroke();

        // Gradient fill under path
        ctx.fillStyle = color + '15';
        ctx.lineTo(startX + (data.length - 1) * step, height - 10);
        ctx.lineTo(startX, height - 10);
        ctx.closePath();
        ctx.fill();
    }
}
