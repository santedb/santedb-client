﻿/*
 * Copyright (C) 2021 - 2025, SanteSuite Inc. and the SanteSuite Contributors (See NOTICE.md for full copyright notices)
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
using SanteDB.Core.Http;
using SanteDB.Core.Interop;
using SanteDB.Core.Interop.Clients;
using SanteDB.Core.Model;
using SanteDB.Core.Model.Collection;
using SanteDB.Core.Model.Patch;
using SanteDB.Core.Model.Query;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq.Expressions;
using System.Reflection;
using System.Text;
using System.Xml.Serialization;

namespace SanteDB.Messaging.HDSI.Client
{
    /// <summary>
    /// Represents the HDSI service client.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class HdsiServiceClient : ServiceClientBase, IDisposable
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HdsiServiceClient"/> class
        /// with a specific <see cref="IRestClient"/> instance.
        /// </summary>
        /// <param name="client">The <see cref="IRestClient"/> instance.</param>
        public HdsiServiceClient(IRestClient client) : base(client)
        {
        }

        /// <summary>
        /// Creates specified data.
        /// </summary>
        /// <typeparam name="TModel">The type of data to be created.</typeparam>
        /// <param name="data">The data to be created.</param>
        /// <returns>Returns the newly created data.</returns>
        public TModel Create<TModel>(TModel data) where TModel : IdentifiedData
        {
            return this.Create(data, false);
        }

        /// <summary>
        /// Creates specified data.
        /// </summary>
        /// <typeparam name="TModel">The type of data to be created.</typeparam>
        /// <param name="data">The data to be created.</param>
        /// <returns>Returns the newly created data.</returns>
        /// <param name="asBundle">True if the result should be returned as a bundle</param>
        public TModel Create<TModel>(TModel data, bool asBundle) where TModel : IdentifiedData
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            // Resource name
            String resourceName = typeof(TModel).GetTypeInfo().GetCustomAttribute<XmlTypeAttribute>().TypeName;

            // Create with version?
            if (data.Key != null && !asBundle)
            {
                return this.Client.Post<TModel, TModel>(String.Format("{0}/{1}", resourceName, data.Key), data);
            }
            else
            {
                if (asBundle)
                {
                    return this.Client.Post<Bundle, TModel>(resourceName, Bundle.CreateBundle(data));
                }
                else
                {
                    return this.Client.Post<TModel, TModel>(resourceName, data);
                }
            }
        }

        /// <summary>
        /// Gets a specified object by key and an optional version key.
        /// </summary>
        /// <typeparam name="TModel">The type of data for which to retrieve.</typeparam>
        /// <param name="key">The key of the data.</param>
        /// <param name="versionKey">The version key of the data.</param>
        /// <returns>Returns the specified data.</returns>
        public TModel Get<TModel>(Guid key, Guid? versionKey) where TModel : IdentifiedData
        {
            // Resource name
            String resourceName = typeof(TModel).GetTypeInfo().GetCustomAttribute<XmlTypeAttribute>().TypeName;

            // URL
            StringBuilder url = new StringBuilder(resourceName);

            url.AppendFormat("/{0}", key);

            if (versionKey.HasValue)
            {
                url.AppendFormat("/history/{0}", versionKey);
            }

            // Optimize?
            return this.Client.Get<TModel>(url.ToString());
        }

        /// <summary>
        /// Gets history of the specified object.
        /// </summary>
        /// <typeparam name="TModel">The type of object for which to retrieve history.</typeparam>
        /// <param name="key">The key of the object.</param>
        /// <returns>Returns a bundle containing the history of the object.</returns>
        public Bundle History<TModel>(Guid key) where TModel : IdentifiedData
        {
            // Resource name
            String resourceName = typeof(TModel).GetTypeInfo().GetCustomAttribute<XmlTypeAttribute>().TypeName;

            // URL
            StringBuilder url = new StringBuilder(resourceName);
            url.AppendFormat("/{0}/history", key);

            // Request
            return this.Client.Get<Bundle>(url.ToString());
        }

        /// <summary>
        /// Obsoletes the specified data.
        /// </summary>
        /// <typeparam name="TModel">The type of data to be obsoleted.</typeparam>
        /// <param name="data">The data to obsolete.</param>
        /// <returns>Returns the obsoleted data.</returns>
        public TModel Obsolete<TModel>(TModel data) where TModel : IdentifiedData
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            // Resource name
            var resourceName = typeof(TModel).GetTypeInfo().GetCustomAttribute<XmlTypeAttribute>().TypeName;

            // Create with version?
            if (data.Key != null)
            {
                return this.Client.Delete<TModel>($"{resourceName}/{data.Key}");
            }

            throw new KeyNotFoundException(data.Key.ToString());
        }

        /// <summary>
        /// Performs a query.
        /// </summary>
        /// <typeparam name="TModel">The type of object to query.</typeparam>
        /// <param name="query">The query parameters as a LINQ expression.</param>
        /// <returns>Returns a Bundle containing the data.</returns>
        public Bundle Query<TModel>(Expression<Func<TModel, bool>> query) where TModel : IdentifiedData
        {
            return this.Query(query, 0, null);
        }

        /// <summary>
        /// Performs a query.
        /// </summary>
        /// <typeparam name="TModel">The type of object to query.</typeparam>
        /// <param name="query">The query parameters as a LINQ expression.</param>
        /// <param name="offset">The offset of the query.</param>
        /// <param name="count">The count of the query results.</param>
        /// <param name="all">Whether the query should return all nested properties.</param>
        /// <param name="queryId">The stateful query id</param>
        /// <param name="orderBy">The ordering instructions</param>
        /// <returns>Returns a Bundle containing the data.</returns>
        public Bundle Query<TModel>(Expression<Func<TModel, bool>> query, int offset, int? count, bool all, Guid? queryId = null, ModelSort<TModel>[] orderBy = null) where TModel : IdentifiedData
        {
            // Map the query to HTTP parameters
            var queryParms = QueryExpressionBuilder.BuildQuery(query, true);

            queryParms["_offset"] = offset.ToString();

            if (count.HasValue)
            {
                queryParms["_count"] = count.ToString();
            }

            if (all)
            {
                queryParms["_all"] = true.ToString();
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
            string resourceName = typeof(TModel).GetTypeInfo().GetCustomAttribute<XmlTypeAttribute>().TypeName;

            // The HDSI uses the XMLName as the root of the request
            var retVal = this.Client.Get<Bundle>(resourceName, queryParms);

            // Return value
            return retVal;
        }

        /// <summary>
        /// Performs a query.
        /// </summary>
        /// <typeparam name="TModel">The type of object to query.</typeparam>
        /// <param name="query">The query parameters as a LINQ expression.</param>
        /// <param name="offset">The offset of the query.</param>
        /// <param name="count">The count of the query results.</param>
        /// <returns>Returns a Bundle containing the data.</returns>
        /// <param name="orderBy">The ordering instructions</param>
        /// <param name="queryId">The stateful query identifier</param>
        public Bundle Query<TModel>(Expression<Func<TModel, bool>> query, int offset, int? count, Guid? queryId = null, ModelSort<TModel>[] orderBy = null) where TModel : IdentifiedData
        {
            // Map the query to HTTP parameters
            var queryParms = QueryExpressionBuilder.BuildQuery(query, true);

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
                    queryParms.Add("_orderBy", QueryExpressionBuilder.BuildSortExpression(itm));
                }
            }

            // Resource name
            string resourceName = typeof(TModel).GetTypeInfo().GetCustomAttribute<XmlTypeAttribute>().TypeName;

            // The HDSI uses the XMLName as the root of the request
            var retVal = this.Client.Get<Bundle>(resourceName, queryParms);

            // Return value
            return retVal;
        }

        /// <summary>
        /// Updates a specified object.
        /// </summary>
        /// <typeparam name="TModel">The type of data to be updated.</typeparam>
        /// <param name="data">The data to be updated.</param>
        /// <returns>Returns the updated data.</returns>
        public TModel Update<TModel>(TModel data) where TModel : IdentifiedData
        {
            return this.Update(data, false);
        }

        /// <summary>
        /// Updates a specified object.
        /// </summary>
        /// <typeparam name="TModel">The type of data to be updated.</typeparam>
        /// <param name="data">The data to be updated.</param>
        /// <param name="asBundle">True if the result should be returned as a bundle</param>
        /// <returns>Returns the updated data.</returns>
        public TModel Update<TModel>(TModel data, bool asBundle) where TModel : IdentifiedData
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            // Resource name
            String resourceName = typeof(TModel).GetTypeInfo().GetCustomAttribute<XmlTypeAttribute>().TypeName;

            // Create with version?
            if (data.Key == null && typeof(TModel) != typeof(Bundle))
            {
                throw new KeyNotFoundException();
            }

            if (data.Key == null && typeof(TModel) == typeof(Bundle))
            {
                data.Key = Guid.NewGuid();
            }

            return asBundle ?
                this.Client.Put<Bundle, TModel>(String.Format("{0}/{1}", resourceName, data.Key.Value), Bundle.CreateBundle(data)) :
                this.Client.Put<TModel, TModel>(String.Format("{0}/{1}", resourceName, data.Key.Value), data);
        }

        /// <summary>
        /// Sends a patch operation to the server.
        /// </summary>
        /// <param name="patch">The patch containing the information to be patched.</param>
        /// <returns>Returns the updated version GUID.</returns>
        public Guid Patch(Patch patch)
        {
            if (patch == null)
            {
                throw new ArgumentNullException(nameof(patch));
            }

            if (patch.AppliesTo == null)
            {
                throw new InvalidOperationException();
            }

            // Resource name
            string resourceName = patch.AppliesTo.Type.GetTypeInfo().GetCustomAttribute<XmlTypeAttribute>().TypeName;

            // First we determine which resource we're patching patch
            var tag = patch.AppliesTo.Tag;
            var key = patch.AppliesTo.Key;

            var sPatch = patch.Clone() as Patch;
            sPatch.AppliesTo = null;

            var version = this.Client.Patch<Patch>($"{resourceName}/{key.Value}", tag, sPatch);

            return Guid.ParseExact(version, "N");
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

        /// <summary>
        /// Gets the options for the IMS
        /// </summary>
        public ServiceOptions Options()
        {
            return this.Client.Options<ServiceOptions>("/");
        }

        #region IDisposable Support

        private bool disposedValue = false; // To detect redundant calls

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
        // ~HdsiServiceClient() {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

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

        #endregion IDisposable Support
    }
}