package com.tdsata.ourappserver.util;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

//@SuppressWarnings("all")
public class SQLTools {
    /**
     * 主数据表中temp字段的字段名.
     */
    public static final String tempKey = "temp";
    /**
     * 储存签到活动信息的数据表表名.
     */
    public static final String signInActivityInfo = "sign_in_activity_info";
    /**
     * 储存部门介绍的数据表表名.
     */
    public static final String departmentInfo = "department_info";
    //-------------------类私有成员----------------------
    private final JdbcTemplate jdbcTemplate;

    public SQLTools(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * 向数据表中插入数据.
     *
     * @param tableName 指定操作的数据表名
     * @param keyAndValue 键值组合，以 key, value, key, value, ... 形式组合
     *                    若键值参数数目不为偶数，将插入失败
     */
    public void insertDataInDBTable(String tableName, String... keyAndValue) throws Exception {
        if (keyAndValue.length % 2 != 0) {
            throw new Exception("插入数据的键值组合参数个数错误");
        }
        StringBuilder columnName = new StringBuilder();
        StringBuilder columnData = new StringBuilder();
        for (int i = 0; i < keyAndValue.length; i += 2) {
            columnName.append(keyAndValue[i]);
            columnData.append('\'');
            columnData.append(keyAndValue[i + 1]);
            columnData.append('\'');
            if (i != keyAndValue.length - 2) {
                columnName.append(", ");
                columnData.append(", ");
            }
        }
        jdbcTemplate.update("insert " + tableName + "(" + columnName + ") values" + "(" + columnData + ")");
    }

    /**
     * 从数据表删除数据.
     *
     * @param tableName 指定操作的数据表名
     * @param condition 删除操作的限定条件
     */
    public void delDataFromDBTable(String tableName, String condition) throws DataAccessException {
        if (condition == null) {
            condition = "";
        } else if (!condition.equals("")) {
            condition = " where " + condition;
        }
        jdbcTemplate.update("delete from " + tableName + condition);
    }

    /**
     * 查询数据表.
     *
     * @param tableName 被查询的数据表名
     * @param key 查询数据表中指定列的列名，模糊查询仅可使用“*”
     * @return 返回由Map构成的List集合，Map中的键与查询的key值一一对应
     *         若无查询结果，则返回null
     */
    public List<Map<String, Object>> queryDBTable(String tableName, String condition, String... key) throws DataAccessException {
        if (condition == null) {
            condition = "";
        } else if (!condition.equals("")) {
            condition = " where " + condition;
        }
        StringBuilder keys = new StringBuilder();
        if (key.length == 1 && key[0].equals("*")) {
            keys.append("*");
        } else {
            for (int i = 0; i < key.length; i++) {
                keys.append(key[i]);
                if (i != key.length - 1)
                    keys.append(", ");
            }
        }
        List<Map<String, Object>> list = jdbcTemplate.queryForList("select " + keys + " from " + tableName + condition);
        if (list.size() == 0) {
            return null;
        }
        return list;
    }

    /**
     * 更新数据表中的数据.
     *
     * @param tableName 数据表表名
     * @param condition 为需要更新的数据限定的条件
     * @param keyAndValue 键值组合，以 key, value, key, value, ... 形式组合
     *                    若键值参数数目不为偶数，将更新失败
     */
    public void updateDataForDBTable(String tableName, String condition, String... keyAndValue) throws Exception {
        if (keyAndValue.length % 2 != 0) {
            throw new Exception("更新数据键值组合参数个数错误");
        }
        StringBuilder command = new StringBuilder();
        for (int i = 0; i < keyAndValue.length; i += 2) {
            command.append(keyAndValue[i]);
            command.append(" = '");
            command.append(keyAndValue[i + 1]);
            command.append('\'');
            if (i != keyAndValue.length - 2)
                command.append(", ");
        }
        if (condition == null) {
            condition = "";
        } else if (!condition.equals("")) {
            condition = "where " + condition;
        }
        jdbcTemplate.update("update " + tableName + " set " + command + " " + condition);
    }

    /**
     * 为数据表添加字段.
     *
     * @param tableName 数据表表名
     * @param fieldAndType 添加的字段名及其类型
     * @param constraint 字段的约束条件（主键/外键/自动增加/非空），为空或""将被忽略
     * @param defaultValue 字段的默认值，为空或""将被忽略
     * @param comment 字段的注释，为空或""将被忽略
     * @param location 字段的位置约束（first/after)，为空或""将被忽略
     */
    public void addFieldOnTable(String tableName, String fieldAndType, String constraint, String defaultValue,
                                String comment, String location) throws DataAccessException {
        if (constraint == null) {
            constraint = "";
        } else if (!constraint.equals("")) {
            constraint = " " + constraint;
        }
        if (defaultValue == null) {
            defaultValue = "";
        } else if (!defaultValue.equals("")) {
            defaultValue = " default '" + defaultValue + "'";
        }
        if (comment == null) {
            comment = "";
        } else if (!comment.equals("")) {
            comment = " " + comment;
        }
        if (location == null) {
            location = "";
        } else if (!location.equals("")) {
            location = " " + location;
        }
        jdbcTemplate.execute("alter table " + tableName + " add " + fieldAndType + constraint + defaultValue + comment + location);
    }

    /**
     * 删除数据表中的字段.
     *
     * @param tableName 数据表表名
     * @param fieldNames 需要删除的字段名
     */
    public void delFieldOnTable(String tableName, String... fieldNames) throws DataAccessException {
        if (fieldNames == null || fieldNames.length == 0) {
            return;
        }
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < fieldNames.length; i++) {
            stringBuilder.append("drop ");
            stringBuilder.append(fieldNames[i]);
            if (i < fieldNames.length - 1) {
                stringBuilder.append(", ");
            }
        }
        jdbcTemplate.execute("alter table " + tableName + stringBuilder);
    }

    /**
     * 查询指定表的字段名.
     *
     * @param tableName 数据表表名（勿用``引用）
     * @param filters 在该表中过滤掉的字段名，为空将被忽略
     * @return 包含查询结果的字符串数组，若查询结果为空，则返回null
     */
    public String[] queryFieldName(String tableName, String... filters) throws DataAccessException {
        StringBuilder inCondition = new StringBuilder();
        if (filters != null && filters.length != 0) {
            inCondition.append(" and COLUMN_NAME not in (");
            for (int i = 0; i < filters.length; i++) {
                inCondition.append("'");
                inCondition.append(filters[i]);
                inCondition.append("'");
                if (i < filters.length - 1) {
                    inCondition.append(", ");
                }
            }
            inCondition.append(")");
        }
        List<Map<String, Object>> queryList = jdbcTemplate.queryForList("select COLUMN_NAME from information_schema.COLUMNS where TABLE_NAME = '"
                + tableName + "'" + inCondition);
        if (queryList.size() == 0) {
            return null;
        }
        String[] results = new String[queryList.size()];
        for (int i = 0; i < queryList.size(); i++) {
            results[i] = String.valueOf(queryList.get(i).get("COLUMN_NAME"));
        }
        return results;
    }

    /**
     * 执行指定的MySQL语句.
     *
     * @param sql MySQL语句
     */
    public void executeAny(String sql) throws DataAccessException {
        jdbcTemplate.execute(sql);
    }
}

// 增
//   增加数据    Y
//   增加列      Y
//   增加表
//
// 删
//   删除数据    Y
//   删除列      Y
//   删除表
//
// 查
//   查找数据    Y
//   查所有列名
//   查所有表名
//
// 改
//   修改数据    Y
//   修改列名
//   修改表名
