defmodule ETEA do
  @moduledoc """
  TEA is a 64-bit symmetric block cipher with a 128-bit key and a variable
  number of rounds (32 is recommended). It has a low setup time, and
  depends on a large number of rounds for security, rather than a complex
  algorithm. It was developed by David J. Wheeler and Roger M. Needham,
  and is described at
  <http://www.ftp.cl.cam.ac.uk/ftp/papers/djw-rmn/djw-rmn-tea.html>.

  This module implements TEA encryption.

    ## SEE ALSO

  <http://www.vader.brad.ac.uk/tea/tea.shtml>

  Crypt::CBC, Crypt::Blowfish, Crypt::DES

  # ACKNOWLEDGEMENTS

  - Dave Paris

  For taking the time to discuss and review the initial version of this
  module, making several useful suggestions, and contributing tests.

  - Mike Blazer and Gil Cohen

  For testing under Windows.

  - Tony Cook

  For making the module work under Activeperl, testing on several
  platforms, and suggesting that I probe for features via %Config.

  # AUTHOR

  Michael Martin <mike@instantchannelinc.com>

  Copyright 2017 Instant Channel, Inc. All rights reserved.

  This software is distributed under the terms of the MIT License
  """

  @on_load {:init, 0}

  @doc """
  Initilizes the module by loading NIFs
  """
  def init do
    # Hack to make this work in escripts.
    path = try do
             :filename.join(:code.priv_dir(:etea), 'etea_nif')
           rescue
             FunctionClauseError -> System.get_env("ETEA_NIF_PATH") <> "etea_nif"
           end
    :ok = :erlang.load_nif(path, 0)
  end

  @doc """
  Encrypt a string using TEA
  """
  @spec encrypt(binary, map) :: binary
  def encrypt(<<data :: binary>>, map) do
    raise "NIF eTEA.encrypt/1 not implemented"
  end

  @doc """
  Decrypt a string using TEA
  """
  @spec decrypt(binary, binary) :: binary
  def decrypt(<<data :: binary>>, <<data :: binary>>) do
    raise "NIF eTEA.decrypt/1 not implemented"
  end

end
