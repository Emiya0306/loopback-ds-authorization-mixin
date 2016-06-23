const _ = require('lodash');
const crypto = require('crypto');

module.exports = function (Model, options) {

    const userModelName = options.userModelName || 'user';
    const roleModelName = options.roleModelName || 'role';
    const adminRoleName = options.adminRoleName || 'admin';
    const dataSourcesName = options.dataSourcesName || 'db';
    const guestAccess = options.guestAccess || false;

    Model.getApp((err, app) => {

        const modelBuilder = app.dataSources[dataSourcesName].modelBuilder;

        let role, user = app.models[userModelName];

        modelBuilder.models[roleModelName].on('attached', roleModelSetup);

        Model.beforeRemote('**', checkModelAccessControl);

        function checkModelAccessControl(ctx, unused, next) {

            checkLogin(ctx.req.accessToken).then((accessToken) => {

                return getUserInstanceRole(accessToken.userId);

            }).then((userRoles) => {

                if (isUserAdmin(userRoles)) {
                    throw 'The token is admin user.';
                } else {
                    return getModelInstanceRoles(ctx.instance ? ctx.instance : ctx.args.id, userRoles);
                }

            }).then((roles) => {

                return getMatchedRole(roles);

            }).then((matchedRole) => {

                matchedRole.save();

                return checkAccessControl(ctx.methodString, matchedRole);

            }).then((result) => {

                throw result;

            }).catch((err) => {

                if (err.status !== 401) {
                    next();
                } else {
                    ctx.res.status(err.status);
                    next(new Error(err.message));
                }

            });

        }

        function checkLogin(accessToken) {
            return new Promise((resolve, reject) => {
                if (accessToken) {
                    resolve(accessToken);
                } else {
                    guestAccess ? reject('User not login.') : reject({message: 'User not login.', status: 401});
                }
            })
        }

        function checkAccessControl(methodString, matchedRole) {
            return new Promise((resolve, reject) => {
                if (matchedRole.acl[methodString.replace(/\./g, '_')] === true) {
                    resolve(`${matchedRole.name} has the premission of ${methodString}.`)
                } else {
                    reject({message: `"${matchedRole.name}" cannot get "${methodString}".`, status: 401})
                }
            })
        }

        function getMatchedRole(roles = [[], []]) {
            const userRoles = roles[0], modelRoles = roles[1];

            // Promise返回user在该Model实例中的角色
            return new Promise((resolve, reject) => {
                for (const role of modelRoles) {
                    const roleResult = _.find(userRoles, role);

                    if (roleResult) {
                        resolve(roleResult)
                    }
                }
                // 如果没有,则返回空
                guestAccess ? reject('No matched roles.') : reject({message: 'No matched roles.', status: 401})
            })
        }

        function getModelInstanceRoles(modelInstance, userRoles) {
            return new Promise((resolve, reject) => {

                if (typeof modelInstance === 'string') {
                    // 如果没有实例但有实例id的,获取Model实例
                    return getModelInstance(modelInstance).then((modelInstance) => {
                        // 获取Model实例的所有角色
                        return getModelRoles(modelInstance)
                    }).then((modelRoles) => {
                        // 并且获取user的所有角色,返回给最终Promise
                        resolve([userRoles, modelRoles])
                    })
                } else if (modelInstance) {
                    // 如果有实例的,获取Model实例的所有角色
                    return getModelRoles(modelInstance).then((modelRoles) => {
                        // 并且获取user的所有角色
                        resolve([userRoles, modelRoles])
                    })
                } else {
                    // 如果没有Model实例的,交给ACL控制
                    reject('No Model Instance');
                }
            })
        }

        function getModelInstance(id) {
            return Model.findOne({where: {id: id}})
        }

        function getModelRoles(modelInstance) {
            return modelInstance.roles({})
        }

        function isUserAdmin(userRoles) {
            return _.find(userRoles, {'name': adminRoleName})
        }

        function getUserRole(userInstance) {
            return userInstance.roles({})
        }

        function getUserInstanceRole(userId) {

            return user.findOne({where: {id: userId}}).then((userInstance) => {
                return getUserRole(userInstance)
            })
        }

        function roleModelSetup() {

            role = app.models[roleModelName];

            role.observe('before save', (ctx, next) => {

                const methodListHash = getMethodListHash(app);

                if (ctx.isNewInstance && ctx.instance.name !== adminRoleName) {
                    ctx.instance.acl = getDefaultModelAcl(app);

                    console.log(`Auto create role model Acl.`);

                } else if (ctx.instance.name !== adminRoleName && ctx.instance.acl.aclHash !== methodListHash) {

                    const defaultModelAcl = getDefaultModelAcl(app);

                    for (const oldMethodName in ctx.instance.acl) {
                        if (defaultModelAcl[oldMethodName] === undefined) {
                            delete ctx.instance.acl[oldMethodName];
                        }
                    }

                    for (const newMethodName in defaultModelAcl) {
                        if (ctx.instance.acl[newMethodName] === undefined) {
                            ctx.instance.acl[newMethodName] = false;
                        }
                    }

                    ctx.instance.acl.aclHash = methodListHash;

                    console.log(`Auto refresh role model Acl.`);
                }

                next();
            });

            // 定义当前Model有多个role
            Model.hasMany(role, {as: `${roleModelName}s`, foreignKey: `${Model.modelName}Id`});

            // 定义role只属于一个Model
            role.belongsTo(Model, {foreignKey: `${Model.modelName}Id`});
        }


        function getDefaultModelAcl(app) {

            const hash = crypto.createHash('sha256');

            let defaultMethodAcl = {}, methodList = '';

            app.models().forEach((Model) => {
                if (isModelHasAuthorizationMixins(Model)) {
                    for (const method of Model.sharedClass.methods()) {
                        methodList += method.stringName;
                        defaultMethodAcl[method.stringName.replace(/\./g, '_')] = false;
                    }
                }
            });

            hash.update(methodList);

            defaultMethodAcl.aclHash = hash.digest('base64');

            return defaultMethodAcl;
        }

        function getMethodListHash(app) {
            let methodList = '';

            const hash = crypto.createHash('sha256');

            app.models().forEach((Model) => {

                if (isModelHasAuthorizationMixins(Model)) {
                    for (const method of Model.sharedClass.methods()) {
                        methodList += method.stringName;
                    }
                }
            });

            hash.update(methodList);

            return hash.digest('base64');
        }

        function isModelHasAuthorizationMixins(Model) {
            return Model.settings.mixins && Model.settings.mixins.Authorization;
        }

    })

};
