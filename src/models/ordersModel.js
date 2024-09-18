const db = require('../../config/database');

const OrdersModel = {
    createOrder: async (userId, items, totalAmount) => {
        const result = await pool.query(
            'INSERT INTO orders (user_id, items, total_amount) VALUES ($1, $2, $3) RETURNING *',
            [userId, items, totalAmount]
        );
        return result.rows[0];
    },
    updateOrderStatus: async (orderId, newStatus) => {
        const result = await pool.query('UPDATE orders SET status = $1 WHERE id = $2', [newStatus, orderId]);
        return result.rowCount > 0;
    },
    getOrderById: async (orderId) => {
        const result = await pool.query('SELECT * FROM orders WHERE id = $1', [orderId]);
        return result.rows[0];
    }
};

module.exports = OrdersModel;
