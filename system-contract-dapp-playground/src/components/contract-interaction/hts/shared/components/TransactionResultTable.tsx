/*-
 *
 * Hedera Smart Contracts
 *
 * Copyright (C) 2023 Hedera Hashgraph, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

import Link from 'next/link';
import { ethers } from 'ethers';
import { FiExternalLink } from 'react-icons/fi';
import { AiOutlineMinus } from 'react-icons/ai';
import { Dispatch, SetStateAction } from 'react';
import { MdNavigateBefore, MdNavigateNext } from 'react-icons/md';
import { TransactionResult } from '@/types/contract-interactions/HTS';
import {
  TableContainer,
  Table,
  Thead,
  Tr,
  Th,
  Tbody,
  Td,
  Popover,
  PopoverTrigger,
  Tooltip,
  PopoverContent,
} from '@chakra-ui/react';

/** @dev shared component representing the list of transactions */
interface TransactionResultTablePageProps {
  hederaNetwork: string;
  TRANSACTION_PAGE_SIZE: number;
  currentTransactionPage: number;
  transactionResultStorageKey: string;
  transactionResults: TransactionResult[];
  paginatedTransactionResults: TransactionResult[];
  setCurrentTransactionPage: Dispatch<SetStateAction<number>>;
  API: 'TokenCreate' | 'TokenMint' | 'TokenAssociate' | 'GrantKYC';
  setTransactionResults: Dispatch<SetStateAction<TransactionResult[]>>;
}

export const TransactionResultTable = ({
  API,
  hederaNetwork,
  transactionResults,
  TRANSACTION_PAGE_SIZE,
  setTransactionResults,
  currentTransactionPage,
  setCurrentTransactionPage,
  transactionResultStorageKey,
  paginatedTransactionResults,
}: TransactionResultTablePageProps) => {
  let beginingHashIndex: number, endingHashIndex: number;
  switch (API) {
    case 'TokenCreate':
      beginingHashIndex = 15;
      endingHashIndex = -12;
      break;
    case 'TokenMint':
      beginingHashIndex = 8;
      endingHashIndex = -4;
      break;
    case 'TokenAssociate':
    case 'GrantKYC':
      beginingHashIndex = 10;
      endingHashIndex = -5;
      break;
  }

  return (
    <TableContainer className="flex flex-col gap-3 overflow-x-hidden">
      <Table variant="simple" size={'sm'}>
        <Thead>
          <Tr>
            <Th color={'#82ACF9'} isNumeric className="flex justify-start">
              Index
            </Th>
            <Th color={'#82ACF9'}>Status</Th>
            <Th color={'#82ACF9'}>Transaction hash</Th>
            <Th color={'#82ACF9'}>Token address</Th>
            {API === 'TokenMint' && <Th color={'#82ACF9'}>Recipient</Th>}
            {API === 'TokenAssociate' && <Th color={'#82ACF9'}>Associated Account</Th>}
            {API === 'GrantKYC' && <Th color={'#82ACF9'}>KYCed Account</Th>}
            <Th />
          </Tr>
        </Thead>
        <Tbody>
          {paginatedTransactionResults.map((transactionResult, index) => {
            /** @dev handle removing record */
            const handleRemoveRecord = (targetTransactionResult: TransactionResult) => {
              const filteredItems = transactionResults.filter(
                (transactionResult) => targetTransactionResult.txHash !== transactionResult.txHash
              );
              if (filteredItems.length === 0) {
                localStorage.removeItem(transactionResultStorageKey);
              }
              setTransactionResults(filteredItems);
            };

            return (
              <Tr
                key={transactionResult.txHash}
                className={
                  transactionResult.status === 'sucess'
                    ? 'hover:bg-hedera-green/10'
                    : 'hover:bg-red-400/10'
                }
              >
                {/* index */}
                <Td>
                  <p>{index + (currentTransactionPage - 1) * TRANSACTION_PAGE_SIZE + 1}</p>
                </Td>

                {/* status */}
                <Td>
                  <p
                    className={
                      transactionResult.status === 'sucess' ? `text-hedera-green` : `text-red-400`
                    }
                  >
                    {transactionResult.status.toUpperCase()}
                  </p>
                </Td>

                {/* transaction hash */}
                <Td className="cursor-pointer">
                  <div className="flex gap-1 items-center">
                    <div onClick={() => navigator.clipboard.writeText(transactionResult.txHash)}>
                      <Popover>
                        <PopoverTrigger>
                          <div className="flex gap-1 items-center">
                            <Tooltip label="click to copy transaction hash">
                              {/* {withTokenAddress ? ( */}
                              <p>
                                {transactionResult.txHash.slice(0, beginingHashIndex)}...
                                {transactionResult.txHash.slice(endingHashIndex)}
                              </p>
                            </Tooltip>
                          </div>
                        </PopoverTrigger>
                        <PopoverContent width={'fit-content'} border={'none'}>
                          <div className="bg-secondary px-3 py-2 border-none font-medium">
                            Copied
                          </div>
                        </PopoverContent>
                      </Popover>
                    </div>
                    <Tooltip
                      label={'Explore this transaction on HashScan'}
                      placement="top"
                      fontWeight={'medium'}
                    >
                      <Link
                        href={`https://hashscan.io/${hederaNetwork}/transaction/${transactionResult.txHash}`}
                        target="_blank"
                      >
                        <FiExternalLink />
                      </Link>
                    </Tooltip>
                  </div>
                </Td>

                {/* token address */}
                {(API === 'TokenCreate' || API === 'TokenMint' || API === 'GrantKYC') && (
                  <Td className="cursor-pointer">
                    {transactionResult.tokenAddress ? (
                      <div className="flex gap-1 items-center">
                        <div
                          onClick={() =>
                            navigator.clipboard.writeText(transactionResult.tokenAddress!)
                          }
                        >
                          <Popover>
                            <PopoverTrigger>
                              <div className="flex gap-1 items-center">
                                <Tooltip label="click to copy token address">
                                  <p>
                                    {transactionResult.tokenAddress.slice(0, beginingHashIndex)}...
                                    {transactionResult.tokenAddress.slice(endingHashIndex)}
                                  </p>
                                </Tooltip>
                              </div>
                            </PopoverTrigger>
                            <PopoverContent width={'fit-content'} border={'none'}>
                              <div className="bg-secondary px-3 py-2 border-none font-medium">
                                Copied
                              </div>
                            </PopoverContent>
                          </Popover>
                        </div>
                        <Tooltip
                          label={'Explore this token on HashScan'}
                          placement="top"
                          fontWeight={'medium'}
                        >
                          <Link
                            href={`https://hashscan.io/${hederaNetwork}/token/${transactionResult.tokenAddress}`}
                            target="_blank"
                          >
                            <FiExternalLink />
                          </Link>
                        </Tooltip>
                      </div>
                    ) : (
                      <>
                        {`${ethers.ZeroAddress.slice(
                          0,
                          beginingHashIndex
                        )}...${ethers.ZeroAddress.slice(endingHashIndex)}`}
                      </>
                    )}
                  </Td>
                )}

                {/* associated token address */}
                {API === 'TokenAssociate' && (
                  <Td className="cursor-pointer">
                    {transactionResult.tokenAddresses &&
                    transactionResult.tokenAddresses.length === 1 ? (
                      <div className="flex gap-1 items-center">
                        <div
                          onClick={() =>
                            navigator.clipboard.writeText(transactionResult.tokenAddresses![0])
                          }
                        >
                          <Popover>
                            <PopoverTrigger>
                              <div className="flex gap-1 items-center">
                                <Tooltip label="click to copy token address">
                                  <p>
                                    {transactionResult.tokenAddresses[0].slice(
                                      0,
                                      beginingHashIndex
                                    )}
                                    ...
                                    {transactionResult.tokenAddresses[0].slice(endingHashIndex)}
                                  </p>
                                </Tooltip>
                              </div>
                            </PopoverTrigger>
                            <PopoverContent width={'fit-content'} border={'none'}>
                              <div className="bg-secondary px-3 py-2 border-none font-medium">
                                Copied
                              </div>
                            </PopoverContent>
                          </Popover>
                        </div>
                        <Tooltip
                          label={'Explore this token on HashScan'}
                          placement="top"
                          fontWeight={'medium'}
                        >
                          <Link
                            href={`https://hashscan.io/${hederaNetwork}/token/${transactionResult.tokenAddresses[0]}`}
                            target="_blank"
                          >
                            <FiExternalLink />
                          </Link>
                        </Tooltip>
                      </div>
                    ) : (
                      <div>
                        <Popover>
                          <PopoverTrigger>
                            <div className="flex gap-1 items-center">
                              <Tooltip label="click to show token addresses">
                                <p>Token Combination</p>
                              </Tooltip>
                            </div>
                          </PopoverTrigger>
                          <PopoverContent
                            width={'fit-content'}
                            border={'none'}
                            className="flex flex-col gap-6 bg-secondary px-4 py-3"
                          >
                            {transactionResult.tokenAddresses?.map((token) => (
                              <div
                                key={token}
                                className="bg-secondary border-none font-medium flex gap-1"
                              >
                                <div onClick={() => navigator.clipboard.writeText(token)}>
                                  <Popover>
                                    <PopoverTrigger>
                                      <div className="flex gap-1 items-center">
                                        <Tooltip label="click to copy token address">
                                          <p>
                                            {token.slice(0, beginingHashIndex)}
                                            ...
                                            {token.slice(endingHashIndex)}
                                          </p>
                                        </Tooltip>
                                      </div>
                                    </PopoverTrigger>
                                    <PopoverContent width={'fit-content'} border={'none'}>
                                      <div className="bg-secondary px-3 py-2 border-none font-medium">
                                        Copied
                                      </div>
                                    </PopoverContent>
                                  </Popover>
                                </div>
                                <Tooltip
                                  label={'Explore this token on HashScan'}
                                  placement="top"
                                  fontWeight={'medium'}
                                >
                                  <Link
                                    href={`https://hashscan.io/${hederaNetwork}/token/${token}`}
                                    target="_blank"
                                  >
                                    <FiExternalLink />
                                  </Link>
                                </Tooltip>
                              </div>
                            ))}
                          </PopoverContent>
                        </Popover>
                      </div>
                    )}
                  </Td>
                )}

                {/* Account address */}
                {(API === 'TokenMint' || API === 'TokenAssociate' || API === 'GrantKYC') && (
                  <Td className="cursor-pointer">
                    {transactionResult.accountAddress ? (
                      <div className="flex gap-1 items-center">
                        <div
                          onClick={() =>
                            navigator.clipboard.writeText(transactionResult.accountAddress!)
                          }
                        >
                          <Popover>
                            <PopoverTrigger>
                              <div className="flex gap-1 items-center">
                                <Tooltip label="click to copy recipient address">
                                  <p>
                                    {transactionResult.accountAddress!.slice(0, beginingHashIndex)}
                                    ...
                                    {transactionResult.accountAddress!.slice(endingHashIndex)}
                                  </p>
                                </Tooltip>
                              </div>
                            </PopoverTrigger>
                            <PopoverContent width={'fit-content'} border={'none'}>
                              <div className="bg-secondary px-3 py-2 border-none font-medium">
                                Copied
                              </div>
                            </PopoverContent>
                          </Popover>
                        </div>
                        <Tooltip
                          label={'Explore this user on HashScan'}
                          placement="top"
                          fontWeight={'medium'}
                        >
                          <Link
                            href={`https://hashscan.io/${hederaNetwork}/account/${transactionResult.accountAddress}`}
                            target="_blank"
                          >
                            <FiExternalLink />
                          </Link>
                        </Tooltip>
                      </div>
                    ) : (
                      <>
                        {API === 'TokenMint'
                          ? 'Treasury Account'
                          : `${ethers.ZeroAddress.slice(
                              0,
                              beginingHashIndex
                            )}...${ethers.ZeroAddress.slice(endingHashIndex)}`}
                      </>
                    )}
                  </Td>
                )}

                {/* delete button */}
                <Td>
                  <Tooltip label="delete this record" placement="top">
                    <button
                      onClick={() => {
                        handleRemoveRecord(transactionResult);
                      }}
                      className={`border border-white/30 px-1 py-1 rounded-lg flex items-center justify-center cursor-pointer hover:bg-red-400 transition duration-300`}
                    >
                      <AiOutlineMinus />
                    </button>
                  </Tooltip>
                </Td>
              </Tr>
            );
          })}
        </Tbody>
      </Table>
      {/* pagination buttons */}
      <div className="flex gap-3 justify-center items-center">
        <Tooltip label="Return to the previous page">
          <button
            onClick={() => setCurrentTransactionPage((prev) => prev - 1)}
            disabled={currentTransactionPage === 1}
            className={`border rounded-lg border-white/30 text-2xl ${
              currentTransactionPage === 1
                ? 'hover:cursor-not-allowed text-white/30'
                : 'hover:cursor-pointer text-white'
            }`}
          >
            <MdNavigateBefore />
          </button>
        </Tooltip>
        <p className="text-base">{currentTransactionPage}</p>
        <Tooltip label="Proceed to the next page">
          <button
            onClick={() => setCurrentTransactionPage((prev) => prev + 1)}
            disabled={paginatedTransactionResults.length < TRANSACTION_PAGE_SIZE}
            className={`border border-white/30 rounded-lg text-2xl cursor-pointer ${
              paginatedTransactionResults.length < TRANSACTION_PAGE_SIZE
                ? 'hover:cursor-not-allowed text-white/30'
                : 'hover:cursor-pointer text-white'
            }`}
          >
            <MdNavigateNext />
          </button>
        </Tooltip>
      </div>
    </TableContainer>
  );
};