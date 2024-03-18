/*
 * Copyright (C) 2021 - 2024, SanteSuite Inc. and the SanteSuite Contributors (See NOTICE.md for full copyright notices)
 * Copyright (C) 2019 - 2021, Fyfe Software Inc. and the SanteSuite Contributors
 * Portions Copyright (C) 2015-2018 Mohawk College of Applied Arts and Technology
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you 
 * may not use this file except in compliance with the License. You may 
 * obtain a copy of the License at 
 * 
 * http://www.apache.org/licenses/LICENSE-2.0 
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the 
 * License for the specific language governing permissions and limitations under 
 * the License.
 * 
 * User: fyfej
 * Date: 2023-6-21
 */
using SanteDB.Core.Applets.Model;
using SanteDB.Core.Http;
using SanteDB.Core.Interop;
using SanteDB.Core.Interop.Clients;
using SanteDB.Core.Mail;
using SanteDB.Core.Model.AMI.Applet;
using SanteDB.Core.Model.AMI.Auth;
using SanteDB.Core.Model.AMI.Collections;
using SanteDB.Core.Model.AMI.Diagnostics;
using SanteDB.Core.Model.AMI.Logging;
using SanteDB.Core.Model.AMI.Security;
using SanteDB.Core.Model.Audit;
using SanteDB.Core.Model.DataTypes;
using SanteDB.Core.Model.Entities;
using SanteDB.Core.Model.Interfaces;
using SanteDB.Core.Model.Query;
using SanteDB.Core.Model.Security;
using SanteDB.Core.Model.Subscription;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Xml.Serialization;

namespace SanteDB.Messaging.AMI.Client
{
    /// <summary>
    /// Represents the AMI service client.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class AmiServiceClient : ServiceClientBase, IDisposable
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AmiServiceClient"/> class
        /// with a specified <see cref="IRestClient"/> instance.
        /// </summary>
        /// <param name="client">The <see cref="IRestClient"/> instance.</param>
        public AmiServiceClient(IRestClient client) : base(client)
        {
        }

        /// <summary>
        /// Accepts a certificate signing request.
        /// </summary>
        /// <param name="id">The id of the certificate signing request.</param>
        /// <returns>Returns the submission result.</returns>
        public SubmissionResult AcceptCertificateSigningRequest(string id)
        {
            return this.Client.Put<object, SubmissionResult>($"Csr/{id}", null);
        }

        /// <summary>
        /// Add users to role
        /// </summary>
        public void AddUsersToRole(String roleName, string[] userNames)
        {
            var query = new NameValueCollection();
            query["_count"] = "1";
            query["name"] = roleName;
            var roleId = this.Client.Get<AmiCollection>($"{typeof(SecurityRole).GetSerializationName()}", query).CollectionItem.OfType<SecurityRoleInfo>().FirstOrDefault()?.Key;
            if (roleId == null)
            {
                throw new KeyNotFoundException(roleName);
            }
            this.Client.Post<AmiCollection, SecurityRole>($"{typeof(SecurityRole).GetSerializationName()}/{roleId}/user", new AmiCollection(userNames.Select(o => new SecurityUser() { UserName = o })));
        }

        /// <summary>
        /// Gets a specific assigning authority.
        /// </summary>
        /// <param name="id">The id of the assigning authority to retrieve.</param>
        /// <returns>Returns the assigning authority.</returns>
        public IdentityDomain AssigningAuthority(Guid id)
        {
            return this.Client.Get<IdentityDomain>($"AssigningAuthority/{id}");
        }

        /// <summary>
        /// Creates an alert message.
        /// </summary>
        /// <param name="alertMessageInfo">The alert message to be created.</param>
        /// <returns>Returns the created alert message.</returns>
        public MailMessage CreateMailMessage(MailMessage alertMessageInfo)
        {
            return this.Client.Post<MailMessage, MailMessage>("MailMessage", alertMessageInfo);
        }

        /// <summary>
        /// Creates an applet.
        /// </summary>
        /// <returns>Returns the created applet manifest info.</returns>
        public AppletManifestInfo CreateApplet(AppletPackage appletPackage)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                appletPackage.Save(ms);
                ms.Flush();
                return this.Client.Post<byte[], AppletManifestInfo>("Applet", "application/octet-stream", ms.ToArray());
            }
        }

        /// <summary>
        /// Creates a security application.
        /// </summary>
        /// <param name="applicationInfo">The security application to be created.</param>
        /// <returns>Returns the created security application.</returns>
        public SecurityApplicationInfo CreateApplication(SecurityApplicationInfo applicationInfo)
        {
            return this.Client.Post<SecurityApplicationInfo, SecurityApplicationInfo>("SecurityApplication", applicationInfo);
        }

        /// <summary>
        /// Creates an assigning authority.
        /// </summary>
        /// <param name="assigningAuthorityInfo">The assigning authority to be created.</param>
        /// <returns>Returns the created assigning authority.</returns>
        public IdentityDomain CreateIdentityDomain(IdentityDomain assigningAuthorityInfo)
        {
            return this.Client.Post<IdentityDomain, IdentityDomain>("IdentityDomain", assigningAuthorityInfo);
        }

        /// <summary>
        /// Creates the code system.
        /// </summary>
        /// <param name="codeSystem">The code system.</param>
        /// <returns>Returns the created code system.</returns>
        public CodeSystem CreateCodeSystem(CodeSystem codeSystem)
        {
            return this.Client.Post<CodeSystem, CodeSystem>("CodeSystem", codeSystem);
        }

        /// <summary>
        /// Creates a device in the IMS.
        /// </summary>
        /// <param name="device">The device to be created.</param>
        /// <returns>Returns the newly created device.</returns>
        public SecurityDeviceInfo CreateDevice(SecurityDeviceInfo device)
        {
            return this.Client.Post<SecurityDeviceInfo, SecurityDeviceInfo>("SecurityDevice", device);
        }

        /// <summary>
        /// Creates the type of the extension.
        /// </summary>
        /// <param name="extensionType">Type of the extension.</param>
        /// <returns>Returns the created extension type.</returns>
        public ExtensionType CreateExtensionType(ExtensionType extensionType)
        {
            return this.Client.Post<ExtensionType, ExtensionType>("ExtensionType", extensionType);
        }

        /// <summary>
        /// Creates a policy in the IMS.
        /// </summary>
        /// <param name="policy">The policy to be created.</param>
        /// <returns>Returns the newly created policy.</returns>
        public SecurityPolicy CreatePolicy(SecurityPolicy policy)
        {
            return this.Client.Post<SecurityPolicy, SecurityPolicy>("SecurityPolicy", policy);
        }

        /// <summary>
        /// Returns true if <paramref name="userName"/> is in <paramref name="roleName"/>
        /// </summary>
        public bool IsUserInRole(string userName, string roleName)
        {
            var query = new NameValueCollection();
            query["_count"] = "0";
            query["_includeTotal"] = "true";
            query["userName"] = userName;
            query["roles.name"] = roleName;
            return this.Client.Get<AmiCollection>($"{typeof(SecurityUser).GetSerializationName()}", query).Size > 0;
        }

        /// <summary>
        /// Creates a role in the IMS.
        /// </summary>
        /// <param name="role">The role to be created.</param>
        /// <returns>Returns the newly created role.</returns>
        public SecurityRoleInfo CreateRole(SecurityRoleInfo role)
        {
            return this.Client.Post<SecurityRoleInfo, SecurityRoleInfo>("SecurityRole", role);
        }

        /// <summary>
        /// Creates a user in the IMS.
        /// </summary>
        /// <param name="user">The user to be created.</param>
        /// <returns>Returns the newly created user.</returns>
        public SecurityUserInfo CreateUser(SecurityUserInfo user)
        {
            return this.Client.Post<SecurityUserInfo, SecurityUserInfo>("SecurityUser", user);
        }

        /// <summary>
        /// Remove users from role
        /// </summary>
        public void RemoveUsersFromRole(string roleName, string[] users)
        {
            var query = new NameValueCollection();
            query["_count"] = "1";
            query["name"] = roleName;
            var roleId = this.Client.Get<AmiCollection>($"{typeof(SecurityRole).GetSerializationName()}", query).CollectionItem.OfType<SecurityRoleInfo>().FirstOrDefault()?.Key;
            if (roleId == null)
            {
                throw new KeyNotFoundException(roleName);
            }
            foreach (var user in users)
            {
                this.Client.Delete<SecurityRole>($"{typeof(SecurityRole).GetSerializationName()}/{roleId}/user/{user}");
            }
        }

        /// <summary>
        /// Deletes an applet.
        /// </summary>
        /// <param name="appletId">The id of the applet to be deleted.</param>
        /// <returns>Returns the deleted applet.</returns>
        public bool DeleteApplet(string appletId)
        {
            return this.Client.Delete<object>($"Applet/{appletId}") != null;
        }

        /// <summary>
        /// Deletes an application.
        /// </summary>
        /// <param name="applicationId">The id of the application to be deleted.</param>
        /// <returns>Returns the deleted application.</returns>
        public SecurityApplicationInfo DeleteApplication(Guid applicationId)
        {
            return this.Client.Delete<SecurityApplicationInfo>($"SecurityApplication/{applicationId}");
        }

        /// <summary>
        /// Deletes an assigning authority.
        /// </summary>
        /// <param name="assigningAuthorityId">The id of the assigning authority to be deleted.</param>
        /// <returns>Returns the deleted assigning authority.</returns>
        public IdentityDomain DeleteAssigningAuthority(Guid assigningAuthorityId)
        {
            return this.Client.Delete<IdentityDomain>($"AssigningAuthority/{assigningAuthorityId}");
        }

        /// <summary>
        /// Deletes a specified certificate.
        /// </summary>
        /// <param name="certificateId">The id of the certificate to be deleted.</param>
        /// <param name="reason">The reason the certificate is to be deleted.</param>
        /// <returns>Returns the deletion result.</returns>
        public SubmissionResult DeleteCertificate(string certificateId, RevokeReason reason)
        {
            return this.Client.Delete<SubmissionResult>($"Certificate/{certificateId}?reason={reason}");
        }

        /// <summary>
        /// Deletes the code system.
        /// </summary>
        /// <param name="codeSystemId">The code system identifier.</param>
        /// <returns>Returns the deleted code system.</returns>
        public CodeSystem DeleteCodeSystem(Guid codeSystemId)
        {
            return this.Client.Delete<CodeSystem>($"CodeSystem/{codeSystemId}");
        }

        /// <summary>
        /// Deletes a device.
        /// </summary>
        /// <param name="id">The id of the device to be deleted.</param>
        /// <returns>Returns the deleted device.</returns>
        public SecurityDeviceInfo DeleteDevice(Guid id)
        {
            return this.Client.Delete<SecurityDeviceInfo>($"SecurityDevice/{id}");
        }

        /// <summary>
        /// Deletes the type of the extension.
        /// </summary>
        /// <param name="extensionTypeId">The extension type identifier.</param>
        /// <returns>Returns the deleted extension type.</returns>
        public ExtensionType DeleteExtensionType(Guid extensionTypeId)
        {
            return this.Client.Delete<ExtensionType>($"ExtensionType/{extensionTypeId}");
        }

        /// <summary>
        /// Deletes a security policy.
        /// </summary>
        /// <param name="id">The id of the policy to be deleted.</param>
        /// <returns>Returns the deleted policy.</returns>
        public SecurityPolicy DeletePolicy(Guid id)
        {
            return this.Client.Delete<SecurityPolicy>($"SecurityPolicy/{id}");
        }

        /// <summary>
        /// Deletes a security role.
        /// </summary>
        /// <param name="id">The id of the role to be deleted.</param>
        /// <returns>Returns the deleted role.</returns>
        public SecurityRoleInfo DeleteRole(Guid id)
        {
            return this.Client.Delete<SecurityRoleInfo>($"SecurityRole/{id}");
        }

        /// <summary>
        /// Deletes a security user.
        /// </summary>
        /// <param name="id">The id of the user to be deleted.</param>
        /// <returns>Returns the deleted user.</returns>
        public SecurityUserInfo DeleteUser(Guid id)
        {
            return this.Client.Delete<SecurityUserInfo>($"SecurityUser/{id}");
        }

        /// <summary>
        /// Downloads the applet.
        /// </summary>
        /// <param name="appletId">The applet identifier.</param>
        /// <returns>Stream.</returns>
        public Stream DownloadApplet(string appletId)
        {
            return new MemoryStream(this.Client.Get($"Applet/{appletId}"));
        }

        /// <summary>
        /// Retrieves the specified role from the AMI
        /// </summary>
        public AmiCollection FindPolicy(Expression<Func<SecurityPolicy, bool>> query)
        {
            return this.Client.Get<AmiCollection>("SecurityPolicy", QueryExpressionBuilder.BuildQuery(query));
        }

        /// <summary>
        /// Retrieves the specified role from the AMI
        /// </summary>
        public AmiCollection FindRole(Expression<Func<SecurityRole, bool>> query)
        {
            return this.Client.Get<AmiCollection>("SecurityRole", QueryExpressionBuilder.BuildQuery(query));
        }

        /// <summary>
        /// Gets a specific alert.
        /// </summary>
        /// <param name="id">The id of the alert to retrieve.</param>
        /// <returns>Returns the alert.</returns>
        public MailMessage GetMailMessage(Guid id)
        {
            return this.Client.Get<MailMessage>($"MailMessage/{id}");
        }

        /// <summary>
		/// Gets a diagnostic alert.
		/// </summary>
		public DiagnosticReport GetServerDiagnoticReport()
        {
            return this.Client.Get<DiagnosticReport>($"Sherlock/system");
        }

        /// <summary>
        /// Gets a list of alerts.
        /// </summary>
        /// <param name="query">The query expression to use to find the alerts.</param>
        /// <returns>Returns a collection of alerts which match the specified criteria.</returns>
        public AmiCollection GetMailMessages(Expression<Func<MailMessage, bool>> query)
        {
            return this.Client.Get<AmiCollection>("MailMessage", QueryExpressionBuilder.BuildQuery(query));
        }

        /// <summary>
        /// Gets a list of applets for a specific query.
        /// </summary>
        /// <returns>Returns a list of applet which match the specific query.</returns>
        public AmiCollection GetApplets()
        {
            return this.Client.Get<AmiCollection>("Applet");
        }

        /// <summary>
        /// Gets a specific application.
        /// </summary>
        /// <param name="id">The id of the application to retrieve.</param>
        /// <returns>Returns the application.</returns>
        public SecurityApplicationInfo GetApplication(Guid id)
        {
            return this.Client.Get<SecurityApplicationInfo>($"SecurityApplication/{id}");
        }

        /// <summary>
        /// Gets a list applications for a specific query.
        /// </summary>
        /// <returns>Returns a list of application which match the specific query.</returns>
        public AmiCollection GetApplications(Expression<Func<SecurityApplication, bool>> query)
        {
            return this.Client.Get<AmiCollection>("SecurityApplication", QueryExpressionBuilder.BuildQuery(query));
        }

        /// <summary>
        /// Perform a query
        /// </summary>
        public AmiCollection Query<TModel>(Expression<Func<TModel, bool>> expression, int offset, int? count, out int tr, Guid? queryId = null, ModelSort<TModel>[] orderBy = null)
        {
            // Map the query to HTTP parameters
            var queryParms = QueryExpressionBuilder.BuildQuery(expression, true);

            queryParms["_offset"] = offset.ToString();

            if (count.HasValue)
            {
                queryParms["_count"] = count.ToString();
            }

            if (queryId.HasValue)
            {
                queryParms["_queryId"] = queryId.ToString();
            }

            if (orderBy != null)
            {
                foreach (var itm in orderBy)
                {
                    queryParms["_orderBy"] = QueryExpressionBuilder.BuildSortExpression(itm);
                }
            }

            // Resource name
            string resourceName = typeof(TModel).GetTypeInfo().GetCustomAttribute<XmlRootAttribute>()?.ElementName
                ?? typeof(TModel).GetTypeInfo().GetCustomAttribute<XmlTypeAttribute>()?.TypeName;

            // The HDSI uses the XMLName as the root of the request
            var retVal = this.Client.Get<AmiCollection>(resourceName, queryParms);

            tr = retVal.Size;

            // Return value
            return retVal;
        }

        /// <summary>
        /// Gets a list of assigning authorities.
        /// </summary>
        /// <param name="query">The query expression to use to find the assigning authorities.</param>
        /// <returns>Returns a collection of assigning authorities which match the specified criteria.</returns>
        public AmiCollection GetIdentityDomains(Expression<Func<IdentityDomain, bool>> query)
        {
            return this.Client.Get<AmiCollection>("IdentityDomain", QueryExpressionBuilder.BuildQuery(query));
        }


        /// <summary>
        /// Gets a certificate signing request.
        /// </summary>
        /// <param name="id">The id of the certificate signing request to be retrieved.</param>
        /// <returns>Returns a certificate signing request.</returns>
        public SubmissionResult GetCertificateSigningRequest(string id)
        {
            return this.Client.Get<SubmissionResult>($"Csr/{id}");
        }

        /// <summary>
        /// Gets a list of certificate signing requests.
        /// </summary>
        /// <param name="query">The query expression to use to find the certificate signing requests.</param>
        /// <returns>Returns a collection of certificate signing requests which match the specified query.</returns>
        public AmiCollection GetCertificateSigningRequests(Expression<Func<SubmissionInfo, bool>> query)
        {
            return this.Client.Get<AmiCollection>("Csr", QueryExpressionBuilder.BuildQuery(query));
        }

        /// <summary>
        /// Gets the code system.
        /// </summary>
        /// <param name="codeSystemId">The code system identifier.</param>
        /// <returns>Returns a code system.</returns>
        public CodeSystem GetCodeSystem(string codeSystemId)
        {
            return this.Client.Get<CodeSystem>($"CodeSystem/{codeSystemId}");
        }

        /// <summary>
        /// Gets the code systems.
        /// </summary>
        /// <param name="query">The query.</param>
        /// <returns>Returns a list of code systems.</returns>
        public AmiCollection GetCodeSystems(Expression<Func<CodeSystem, bool>> query)
        {
            return this.Client.Get<AmiCollection>("CodeSystem", QueryExpressionBuilder.BuildQuery(query));
        }

        /// <summary>
        /// Gets a specific device.
        /// </summary>
        /// <param name="id">The identifier.</param>
        /// <returns>Returns the security device.</returns>
        public SecurityDeviceInfo GetDevice(Guid id)
        {
            return this.Client.Get<SecurityDeviceInfo>($"SecurityDevice/{id}");
        }

        /// <summary>
        /// Gets a list of devices.
        /// </summary>
        /// <param name="query">The query expression to use to find the devices.</param>
        /// <returns>Returns a collection of devices which match the specified query.</returns>
        public AmiCollection GetDevices(Expression<Func<SecurityDevice, bool>> query)
        {
            return this.Client.Get<AmiCollection>("SecurityDevice", QueryExpressionBuilder.BuildQuery(query));
        }

        /// <summary>
        /// Gets the type of the extension.
        /// </summary>
        /// <param name="extensionTypeId">The extension type identifier.</param>
        /// <returns>Returns the extension type, or null if no extension type is found.</returns>
        public ExtensionType GetExtensionType(Guid extensionTypeId)
        {
            return this.Client.Get<ExtensionType>($"ExtensionType/{extensionTypeId}");
        }

        /// <summary>
        /// Gets the extension types.
        /// </summary>
        /// <param name="expression">The expression.</param>
        /// <returns>Returns a list of extension types.</returns>
        public AmiCollection GetExtensionTypes(Expression<Func<ExtensionType, bool>> expression)
        {
            return this.Client.Get<AmiCollection>("ExtensionType", QueryExpressionBuilder.BuildQuery(expression));
        }

        /// <summary>
        /// Retrieves a specified policy.
        /// </summary>
        /// <param name="query">The query expression to use to find the policy.</param>
        /// <returns>Returns a collection of policies which match the specified query parameters.</returns>
        public AmiCollection GetPolicies(Expression<Func<SecurityPolicy, bool>> query)
        {
            return this.Client.Get<AmiCollection>("SecurityPolicy", QueryExpressionBuilder.BuildQuery(query));
        }

        /// <summary>
        /// Gets a specific policy.
        /// </summary>
        /// <param name="id">The id of the policy to be retrieved.</param>
        /// <returns>Returns the specific policy.</returns>
        public SecurityPolicy GetPolicy(Guid id)
        {
            return this.Client.Get<SecurityPolicy>($"SecurityPolicy/{id}");
        }

        /// <summary>
        /// Gets a specific role.
        /// </summary>
        /// <param name="id">The id of the role to be retrieved.</param>
        /// <returns>Returns the specified role.</returns>
        public SecurityRoleInfo GetRole(Guid id)
        {
            return this.Client.Get<SecurityRoleInfo>($"SecurityRole/{id}");
        }

        /// <summary>
		/// Gets a specific role.
		/// </summary>
		/// <param name="roleName">The id of the role to be retrieved.</param>
		/// <returns>Returns the specified role.</returns>
		public SecurityRoleInfo GetRole(String roleName)
        {
            return this.GetRoles(o => o.Name == roleName).CollectionItem.FirstOrDefault() as SecurityRoleInfo;
        }

        /// <summary>
        /// Retrieves a specified role.
        /// </summary>
        /// <param name="query">The query expression to use to find the role.</param>
        /// <returns>Returns a collection of roles which match the specified query parameters.</returns>
        public AmiCollection GetRoles(Expression<Func<SecurityRole, bool>> query)
        {
            return this.Client.Get<AmiCollection>("SecurityRole", QueryExpressionBuilder.BuildQuery(query));
        }

        /// <summary>
        /// Gets a list of two-factor mechanisms
        /// </summary>
        public AmiCollection GetTwoFactorMechanisms()
        {
            return this.Client.Get<AmiCollection>("Tfa");
        }

        /// <summary>
        /// Gets a list of subscriptions.
        /// </summary>
        /// <returns></returns>
        public AmiCollection GetSubscriptionDefinitions() => this.Client.Get<AmiCollection>("SubscriptionDefinition");
        /// <summary>
        /// 
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public SubscriptionDefinition GetSubscriptionDefinition(Guid id) => this.Client.Get<SubscriptionDefinition>($"SubscriptionDefinition/{id}");

        /// <summary>
        /// Gets a specific user.
        /// </summary>
        /// <param name="id">The id of the user to be retrieved.</param>
        /// <returns>Returns the specified user.</returns>
        public SecurityUserInfo GetUser(Guid id)
        {
            return this.Client.Get<SecurityUserInfo>($"SecurityUser/{id}");
        }

        /// <summary>
        /// Retrieves a specified user.
        /// </summary>
        /// <param name="query">The query expression to use to find the user.</param>
        /// <returns>Returns a collection of users which match the specified query parameters.</returns>
        public AmiCollection GetUsers(Expression<Func<SecurityUser, bool>> query)
        {
            return this.Client.Get<AmiCollection>("SecurityUser", QueryExpressionBuilder.BuildQuery(query));
        }

        /// <summary>
        /// Gets the options for the AMI.
        /// </summary>
        /// <returns>Return the service options for the AMI.</returns>
        public ServiceOptions Options()
        {
            return this.Client.Options<ServiceOptions>("/");
        }

        /// <summary>
        /// Perform a ping
        /// </summary>
        public bool Ping()
        {
            try
            {
                this.Client.Invoke<Object, Object>("PING", "/", null, null);
                return true;
            }
            catch
            {
                return false;
            }
        }

        #region IDisposable Support

        private bool disposedValue = false; // To detect redundant calls

        /// <summary>
        /// Dispose of any resources.
        /// </summary>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // TODO: uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Dispose of any managed resources.
        /// </summary>
        /// <param name="disposing">Whether the current invocation is disposing.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    this.Client?.Dispose();
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~AmiServiceClient() {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        #endregion IDisposable Support

        /// <summary>
        /// Stats the update via a HEAD command
        /// </summary>
        /// <param name="packageId">The package identifier.</param>
        /// <returns>Returns the applet info.</returns>
        public AppletInfo StatUpdate(String packageId)
        {
            var headers = this.Client.Head($"Applet/{packageId}");
            String versionKey = String.Empty,
                packId = String.Empty,
                hash = String.Empty;
            headers.TryGetValue("X-SanteDB-PakID", out packId);
            headers.TryGetValue("ETag", out versionKey);

            return new AppletInfo()
            {
                Id = packageId,
                Version = versionKey
            };
        }

        /// <summary>
        /// Submits a diagnostic report.
        /// </summary>
        /// <param name="report">The diagnostic report.</param>
        /// <returns>Returns the submitted diagnostic report.</returns>
        public void SubmitAudit(AuditEventData report)
        {
            this.Client.Post<AuditEventData, object>("Audit", report);
        }

        /// <summary>
        /// Submits a diagnostic report.
        /// </summary>
        public void SubmitAudit(AuditSubmission submission)
        {
            this.Client.Post<AuditSubmission, object>("Audit", submission);
        }

        /// <summary>
        /// Retrieves an audit
        /// </summary>
        /// <param name="id">The id of the audit to retrieve</param>
        public AuditEventData GetAudit(Guid id)
        {
            return this.Client.Get<AuditEventData>($"Audit/{id}");
        }

        /// <summary>
        /// Retrieves an audit
        /// </summary>
        /// <param name="expression">The query to filter audits on</param>
        public AuditEventData GetAudits(Expression<Func<AuditEventData, bool>> expression)
        {
            return this.Client.Get<AuditEventData>($"Audit", QueryExpressionBuilder.BuildQuery(expression));
        }

        /// <summary>
        /// Submits a certificate signing request to the AMI.
        /// </summary>
        /// <param name="submissionRequest">The certificate signing request.</param>
        /// <returns>Returns the submission result.</returns>
        public SubmissionResult SubmitCertificateSigningRequest(SubmissionRequest submissionRequest)
        {
            return this.Client.Post<SubmissionRequest, SubmissionResult>("Csr", submissionRequest);
        }

        /// <summary>
        /// Submits a diagnostic report.
        /// </summary>
        /// <param name="report">The diagnostic report.</param>
        /// <returns>Returns the submitted diagnostic report.</returns>
        public DiagnosticReport SubmitDiagnosticReport(DiagnosticReport report)
        {
            return this.Client.Post<DiagnosticReport, DiagnosticReport>("Sherlock", report);
        }

        /// <summary>
        /// Updates an alert.
        /// </summary>
        /// <param name="messageId">The id of the alert to be updated.</param>
        /// <param name="mailMessage">The alert message info containing the updated information.</param>
        /// <returns>Returns the updated alert.</returns>
        public MailMessage UpdateMailMessage(Guid messageId, MailMessage mailMessage)
        {
            return this.Client.Put<MailMessage, MailMessage>($"MailMessage/{messageId}", mailMessage);
        }

        /// <summary>
        /// Updates an applet.
        /// </summary>
        /// <param name="appletId">The id of the applet to be updated.</param>
        /// <param name="appletPackage">The applet containing the updated information.</param>
        /// <returns>Returns the updated applet.</returns>
        public AppletManifestInfo UpdateApplet(Guid appletId, AppletPackage appletPackage)
        {
            using (var ms = new MemoryStream())
            {
                appletPackage.Save(ms);
                ms.Flush();
                return this.Client.Put<byte[], AppletManifestInfo>($"Applet/{appletId}", "application/octet-stream", ms.ToArray());
            }
        }

        /// <summary>
        /// Updates an application.
        /// </summary>
        /// <param name="applicationId">The id of the application to be updated.</param>
        /// <param name="applicationInfo">The application containing the updated information.</param>
        /// <returns>Returns the updated application.</returns>
        public SecurityApplicationInfo UpdateApplication(Guid applicationId, SecurityApplicationInfo applicationInfo)
        {
            return this.Client.Put<SecurityApplicationInfo, SecurityApplicationInfo>($"SecurityApplication/{applicationId}", applicationInfo);
        }

        /// <summary>
        /// Updates an assigning authority.
        /// </summary>
        /// <param name="assigningAuthorityId">The id of the assigning authority to be updated.</param>
        /// <param name="assigningAuthorityInfo">The assigning authority info containing the updated information.</param>
        /// <returns>Returns the updated assigning authority.</returns>
        public IdentityDomain UpdateAssigningAuthority(Guid assigningAuthorityId, IdentityDomain assigningAuthorityInfo)
        {
            return this.Client.Put<IdentityDomain, IdentityDomain>($"AssigningAuthority/{assigningAuthorityId}", assigningAuthorityInfo);
        }

        /// <summary>
        /// Updates the code system.
        /// </summary>
        /// <param name="codeSystemId">The code system identifier.</param>
        /// <param name="codeSystem">The code system.</param>
        /// <returns>Return the updated code system.</returns>
        public CodeSystem UpdateCodeSystem(Guid codeSystemId, CodeSystem codeSystem)
        {
            return this.Client.Put<CodeSystem, CodeSystem>($"CodeSystem/{codeSystemId}", codeSystem);
        }

        /// <summary>
        /// Updates a device.
        /// </summary>
        /// <param name="deviceId">The id of the device to be updated.</param>
        /// <param name="deviceInfo">The device containing the updated information.</param>
        /// <returns>Returns the updated device.</returns>
        public SecurityDeviceInfo UpdateDevice(Guid deviceId, SecurityDeviceInfo deviceInfo)
        {
            return this.Client.Put<SecurityDeviceInfo, SecurityDeviceInfo>($"SecurityDevice/{deviceId}", deviceInfo);
        }

        /// <summary>
        /// Updates the type of the extension.
        /// </summary>
        /// <param name="extensionTypeId">The extension type identifier.</param>
        /// <param name="extensionType">Type of the extension.</param>
        /// <returns>Returns the updated extension type.</returns>
        public ExtensionType UpdateExtensionType(Guid extensionTypeId, ExtensionType extensionType)
        {
            return this.Client.Put<ExtensionType, ExtensionType>($"ExtensionType/{extensionTypeId}", extensionType);
        }

        /// <summary>
        /// Updates a role.
        /// </summary>
        /// <param name="roleId">The id of the role to be updated.</param>
        /// <param name="roleInfo">The role containing the updated information.</param>
        /// <returns>Returns the updated role.</returns>
        public SecurityRoleInfo UpdateRole(Guid roleId, SecurityRoleInfo roleInfo)
        {
            return this.Client.Put<SecurityRoleInfo, SecurityRoleInfo>($"SecurityRole/{roleId}", roleInfo);
        }

        /// <summary>
        /// Updates a user.
        /// </summary>
        /// <param name="id">The id of the user to be updated.</param>
        /// <param name="user">The user containing the updated information.</param>
        /// <returns>Returns the updated user.</returns>
        public SecurityUserInfo UpdateUser(Guid id, SecurityUserInfo user)
        {
            return this.Client.Put<SecurityUserInfo, SecurityUserInfo>($"SecurityUser/{id}", user);
        }

        /// <summary>
        /// Get all logs
        /// </summary>
        public AmiCollection GetLogs()
        {
            return this.Client.Get<AmiCollection>("Log");
        }

        /// <summary>
        /// Gets the specified log from the server
        /// </summary>
        public LogFileInfo GetLog(string logId)
        {
            return this.Client.Get<LogFileInfo>($"Log/{logId}");
        }

        /// <summary>
        /// Create a device entity
        /// </summary>
        public DeviceEntity CreateDeviceEntity(DeviceEntity entity)
        {
            return this.Client.Post<DeviceEntity, DeviceEntity>("DeviceEntity", entity);
        }

        /// <summary>
        /// Create a device entity
        /// </summary>
        public ApplicationEntity CreateApplicationEntity(ApplicationEntity entity)
        {
            return this.Client.Post<ApplicationEntity, ApplicationEntity>("ApplicationEntity", entity);
        }

        /// <summary>
        /// Create a device entity
        /// </summary>
        public DeviceEntity UpdateDeviceEntity(Guid id, DeviceEntity entity)
        {
            return this.Client.Put<DeviceEntity, DeviceEntity>($"DeviceEntity/{id}", entity);
        }

        /// <summary>
        /// Create a device entity
        /// </summary>
        public ApplicationEntity UpdateApplicationEntity(Guid id, ApplicationEntity entity)
        {
            return this.Client.Put<ApplicationEntity, ApplicationEntity>($"ApplicationEntity/{id}", entity);
        }

        /// <summary>
        /// Create a device entity
        /// </summary>
        public AmiCollection GetApplicationEntities(Expression<Func<ApplicationEntity, bool>> expression)
        {
            return this.Client.Get<AmiCollection>("ApplicationEntity", QueryExpressionBuilder.BuildQuery(expression));
        }

        /// <summary>
        /// Create a device entity
        /// </summary>
        public AmiCollection GetDeviceEntities(Expression<Func<DeviceEntity, bool>> expression)
        {
            return this.Client.Get<AmiCollection>("DeviceEntity", QueryExpressionBuilder.BuildQuery(expression));
        }

        /// <summary>
        /// Get all applet solutions from server
        /// </summary>
        public AmiCollection GetAppletSolutions()
        {
            return this.Client.Get<AmiCollection>("AppletSolution");
        }

        /// <summary>
        /// Get applet solution
        /// </summary>
        public AppletSolutionInfo GetAppletSolution(string solutionId)
        {
            return this.Client.Get<AppletSolutionInfo>($"AppletSolution/{solutionId}");
        }

        /// <summary>
        /// Create applet solution
        /// </summary>
        public AppletSolutionInfo CreateAppletSolution(AppletSolution solution)
        {
            return this.Client.Post<AppletSolution, AppletSolutionInfo>("AppletSolution", solution);
        }

        /// <summary>
        /// Update applet solution
        /// </summary>
        public AppletSolutionInfo UpdateAppletSolution(String solutionId, AppletSolutionInfo solution)
        {
            return this.Client.Put<AppletSolutionInfo, AppletSolutionInfo>($"AppletSolution/{solutionId}", solution);
        }

        /// <summary>
        /// Obsoletes the applet solution
        /// </summary>
        public AppletSolutionInfo ObsoleteAppletSolution(string solutionId)
        {
            return this.Client.Delete<AppletSolutionInfo>($"AppletSolution/{solutionId}");
        }

        /// <summary>
        /// Get the specified provenance object
        /// </summary>
        public SecurityProvenance GetProvenance(Guid provenanceId)
        {
            return this.Client.Get<SecurityProvenance>($"SecurityProvenance/{provenanceId}");
        }

        /// <summary>
        /// Lock user
        /// </summary>
        public SecurityUserInfo LockUser(Guid userId)
        {
            return this.Client.Lock<SecurityUserInfo>($"SecurityUser/{userId}");
        }

        /// <summary>
        /// Unlock user
        /// </summary>
        public SecurityUserInfo UnlockUser(Guid userId)
        {
            return this.Client.Unlock<SecurityUserInfo>($"SecurityUser/{userId}");
        }

        /// <summary>
        /// Add policy <paramref name="policyOid"/> to <paramref name="securable"/>
        /// </summary>
        public void AddPolicy(IAnnotatedResource securable, string policyOid, PolicyGrantType rule)
        {
            this.Client.Post<SecurityPolicyInfo, SecurityPolicyInfo>($"{securable.GetType().GetSerializationName()}/{securable.Key}/policy", new SecurityPolicyInfo()
            {
                Oid = policyOid,
                Grant = rule
            });
        }
    }
}